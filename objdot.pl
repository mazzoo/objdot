#!/usr/bin/perl -w
#
########################################################################
#
# objdot.pl - generate callflow graphs through static analysis
#             using objdump and dot/graphviz
#
#
# by Matthias Wenzel a.k.a. mazzoo in 2010
#
#
# software license: GPLv3
#
########################################################################



#use strict; # FIXME someone tell me how to use
             #       function pointer tables strict

use feature "switch";
use File::stat;

#$| = 1;

########################################################################
#
# tweak some or most of these settings below
#
########################################################################

# arch
# x86_syntax
# x86_mode
# arm_mode
#     these determine your CPU architecture, disassembler syntax and
#     real/protected mode (x86), thumb/32bit (arm) etc.

my $arch       = "i386";  # i386 for now, arm tbd

my $x86_syntax = "att";   # intel or att

my $x86_mode   = "16";    # cpu mode 16/32 bit at startup

my $arm_mode   = "thumb"; # cpu mode 16/32 bit at startup

# start_offset : file offset at which disassembly starts
#     negative means offset from the end of the file
#     e.g. for a x86 BIOS you'd say -16 here (x86 reset vector
#
#my $start_offset = -0x10; # reset vector is 16 bytes before end
my $start_offset = 3; # for PCI option ROMs (e.g. a Video BIOS)


# disassembler - tweak objdump to your needs here...

my $dis_basic = "objdump -D -m $arch -b binary ";

my $dis = $dis_basic;
$dis .= " -M $x86_syntax "   if ($arch eq "i386");
$dis .= " -M data16,addr16 " if ($x86_mode == "16");

my @bb; # array of building blocks. each entry contains
        # - start_addr of the block
        # - addr_next last address +1 of that bb - currently unused
        # - cpu mode
        # - list of mnemonics for that bb
        # - list of hex opcodes for that mnemonic
        # - list of successors of this bb (can have zero, one or two entries)

my $min_disassembly_bytes = 0x1000;


# CPU mode detection is crappy. very crappy.
# here with %toggle_cpu_mode you can mark bb where the detection
# has gone wrong (only list the root bb that was detected wrong -
# subsequent branches will be toggled implicitely)

my %toggle_cpu_mode = (
#	0x7f82c => "1",
#	0x7f87d => "1",
#	0x7fafc => "1",
#	0x7fb2e => "1",
);


# the automated static analysis herein often doesn't find all bb
# (we run no simulation) but by reading the code humans often find
# more and more start addresses for bb. list them here iteratively.

my @extra_bb = (
#	[0x7f860, "32"],
#	[0x7f8ee, "32"],
#	[0x7fbe7, "32"],
#	[0x7fbf7, "32"],
#	[0x7fc01, "32"],
#	[0x7f8f8, "32"],
#	[0x7f922, "32"],
#	[0x7f92c, "32"],
);

########################################################################
#
# end of tweakables
#
########################################################################

my $file_name;
my $file_size = 0;

my %have_bb_for_addr;

sub split_bb($$)
{
	my $index      = shift;
	my $split_addr = shift;

	my @old_bb = splice(@bb, $index, 1);

	my $cpu_mode    = $old_bb[0][2];
	my $this_bb_ops = $old_bb[0][3];

	my $op;
	my $op_count = 0;
	foreach $op (@$this_bb_ops)
	{
		last if @$op[0] == $split_addr;
		$op_count++;
	}

	if ($op_count == $#$this_bb_ops + 1)
	{
		print "l33t binary jumps into middle of opcodes\n";
		# push back original bb
		push @bb, @old_bb;
		# add new address
		push @extra_bb, [ $split_addr, $cpu_mode ];
		return;
	}

	$have_bb_for_addr{$split_addr} = 1;

	my @bb_ops_1st = splice(@$this_bb_ops, 0, $op_count);
	my @bb_ops_2nd = @$this_bb_ops;

	my @successors_1st = ($bb_ops_2nd[0][0]);
	my $successors_2nd = $old_bb[0][4];

	my @bb_1st = [ ($old_bb[0][0], $split_addr, $cpu_mode, [@bb_ops_1st], [@successors_1st] ) ];
	my @bb_2nd = [ ($split_addr, $old_bb[0][1], $cpu_mode, [@bb_ops_2nd], [@$successors_2nd] ) ];

	push @bb, @bb_1st;
	push @bb, @bb_2nd;
}

sub we_have_bb_for_addr($)
{
	my $a = shift;

	# cache of existing bb
	return 1 if (exists $have_bb_for_addr{$a});

	my $i;
	for $i ( 0 .. $#bb )
	{
		if ( ( hex($bb[$i][0]) < hex($a) ) &&
		     ( hex($a) < hex($bb[$i][1]) ) )
		{
			split_bb($i, $a);
			return 1;
		}
	}
	return 0;
}

# functions for calculating dest addresses
sub first_match($$$$)
{
	my $addr_next = shift;
	my $a0 = shift;
	if (!$a0)
	{
		print "FIXME\n";
		return 0;
	}
	my $result = hex($a0);
	$result &= $file_size-1;
	return $result;
}

sub addr_segment_offset($$$$)
{
	my $addr_next = shift;
	my $a0 = shift;
	my $a1 = shift;
	my $result = 0;
	if (!$a0)
	{
		print "FIXME\n";
	}
	if (!$a1)
	{
		print "FIXME\n";
	}
	# gate A20 stuph
	if ($x86_mode == "16")
	{
		$result = hex($a0) * 0x10 + hex($a1);
		$result &= 0xfffff;
		# but don't leave the current segment
		$result += $addr_next & 0xfff00000;
	}
	if ($x86_mode == "32")
	{
		$result = hex($a0) * 0x10000 + hex($a1);
	}
	$result &= $file_size - 1;
	return $result;
}

sub addr_next($$$$)
{
	my $addr_next = shift;
	return $addr_next;
}

# FLAG definitions for opcodes:
#
# FLAG_JCC   - e.g. conditional jump - next addr is a new bb
# FLAG_CALL  - e.g. call - next addr is a new bb, uses stack
# FLAG_JUMP  - e.g. jmp - next addr is not used
# FLAG_FINAL - e.g. hlt - no subsequent opcodes
# FLAG_MODE  - e.g. mov 1,%cr0 - switch to 32bit protected mode
# FLAG_FIXME - e.g. something that is not yet fully supported in objdot

my $FLAG_JCC   = 0x0001;
my $FLAG_CALL  = 0x0002;
my $FLAG_JUMP  = 0x0004;
my $FLAG_FINAL = 0x0008;
my $FLAG_MODE  = 0x0010;
my $FLAG_FIXME = 0x8000;

# @ops_x86_att_16 - list of opcodes that terminate a bb
# opcode (regex),
#   FLAG(s),
#     regex for extracting parameters,
#       function name calculating addr_dest

my @ops_x86_att_16 = (
	["call",     $FLAG_CALL, "[^:]0x([a-fA-F0-9]+)", "first_match"],
	["lcall",    $FLAG_CALL, "", ],
	["int",      $FLAG_CALL, "", ],
	["ja",       $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["jae",      $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["jb",       $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["jbe",      $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["jc",       $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["jcxz",     $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["jecxz",    $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["je",       $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["jg",       $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["jge",      $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["jl",       $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["jle",      $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["jna",      $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["jnae",     $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["jnb",      $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["jnbe",     $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["jnc",      $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["jne",      $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["jng",      $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["jnge",     $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["jnl",      $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["jnle",     $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["jno",      $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["jnp",      $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["jns",      $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["jnz",      $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["jo",       $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["jp",       $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["jpe",      $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["jpo",      $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["js",       $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["jz",       $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["loop\\s",  $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["loope\\s", $FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["loopne\\s",$FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["loopnz\\s",$FLAG_JCC, "0x([a-fA-F0-9]+)", "first_match"],
	["jmp\\s",   $FLAG_JUMP, "0x([a-fA-F0-9]+)", "first_match"],
	["ljmp\\s",  $FLAG_JUMP, "0x([a-fA-F0-9]+),.*0x([a-fA-F0-9]+)", "addr_segment_offset"],
	["ljmpl\\s", $FLAG_JUMP, "", ],
	["ljmpw\\s", $FLAG_JUMP, "0x([a-fA-F0-9]+),.*0x([a-fA-F0-9]+)", "addr_segment_offset"],
	["iret",     $FLAG_FINAL, "", ],
	["lret",     $FLAG_FINAL, "", ],
	["ret",      $FLAG_FINAL, "", ],
	["hlt",      $FLAG_FINAL, "", ],
	["\\(bad\\)",  $FLAG_FINAL,"", ],
	["mov.*,%cr0", $FLAG_MODE, ".*", "addr_next"],
);

sub is_jmp($)
{
	my $mnemo = shift;

	my $jmp_ref;
	for $jmp_ref (@ops_x86_att_16)
	{
		my $pattern = "@$jmp_ref[0]";
		if ( $mnemo =~ /^$pattern/ )
		{
			return @$jmp_ref;
		}
	}

	return ();
}

sub switches_cpu_mode($)
{
	my $mnemo = shift;

	my $bb_mode = $x86_mode;

	if ( $mnemo =~ /^mov.*,%cr0/ )
	{
		if ($bb_mode == "16")
		{
			$bb_mode = "32";
		}else{
			$bb_mode = "16";
		}
		print "new CPU mode $bb_mode bit\n";
		return $bb_mode;
	}
	return 0;
}

sub do_next_bb($$);
sub do_next_bb($$)
{
	my $start_addr = shift;
	$x86_mode = shift;

	return if (we_have_bb_for_addr($start_addr));
	$have_bb_for_addr{$start_addr} = 1;

        if (exists $toggle_cpu_mode{$start_addr}){
		if ($x86_mode == "16")
		{
			$x86_mode = "32";
		}else{
			$x86_mode = "16";
		}
	}

	$dis = $dis_basic;
	$dis .= " -M $x86_syntax "   if ($arch eq "i386");
	$dis .= " -M data16,addr16 " if ($x86_mode == "16");

	my $stop_addr = $start_addr + $min_disassembly_bytes;
	my $cmd = "$dis --start-addr=$start_addr --stop-addr=$stop_addr $file_name";

	#print "$cmd\n";

	open DIS, "$cmd|" or die "can't run $cmd: $!\n";

	print "\n";

	my @this_bb     = ();
	my @this_bb_ops = ();
	my @successors  = ();
	while (<DIS>)
	{
		if (/^([ 0-9a-fA-F]+):\t([ 0-9a-fA-F]+)\t(.*)$/) # a mnemonic after all
		{
			my $addr  = $1;
			my $hexop = $2;
			my $mnemo = $3;

			# strip leading and trailing whitespaces
			$addr  =~ s/\s+//;
			$hexop =~ s/^\s+//;
			$hexop =~ s/\s+$//;
			$mnemo =~ s/^\s+//;
			$mnemo =~ s/\s+$//;
			$addr  =  hex($addr);

			printf "0x%8.8x :: %-35s | %s\n", $addr, $mnemo, $hexop;

			push @this_bb_ops, [ ($addr, $hexop, $mnemo) ];

			my @op_type;
			if (@op_type = is_jmp($mnemo))
			{
				close DIS;
				my $addr_next;
				my @hexop_array = split(/ /, $hexop);
				$addr_next = $addr + $#hexop_array + 1;

				if (($op_type[1] & $FLAG_CALL) ||
				    ($op_type[1] & $FLAG_JCC ) ||
				    ($op_type[1] & $FLAG_MODE) )
				{
					push @successors, $addr_next;
				}
				if (!($op_type[1] & $FLAG_FINAL))
				{
					if ($mnemo =~ /$op_type[2]/)
					{
						my $addr_dest = $op_type[3]->($addr_next, $1, $2, $3);
						push @successors, $addr_dest;
					}else{
						print "FIXME\n";
						# lets add that FIXME to the opcode...
						pop @this_bb_ops;
						$mnemo .= " FIXME";
						push @this_bb_ops, [ ($addr, $hexop, $mnemo) ];
					}
				}
				my $new_mode = $x86_mode;
				if ($op_type[1] & $FLAG_MODE)
				{
					$new_mode = switches_cpu_mode($mnemo);
					if ($new_mode)
					{
						pop @this_bb_ops;
						$mnemo .= " new CPU mode $new_mode";
						push @this_bb_ops, [ ($addr, $hexop, $mnemo) ];
					}else{
						$new_mode = $x86_mode;
					}
				}

				push @bb, [ ($start_addr, $addr_next, $x86_mode, [@this_bb_ops], [@successors] ) ];

				for (@successors)
				{
					do_next_bb($_, $new_mode);
				}
				return;
			}
		} # a mnemonic after all
	} # while (<DIS>)
}

sub dump_dot_file()
{
	my $dot_file_name = $file_name . ".dot";
        open (DOT, ">$dot_file_name") or die("can't open $dot_file_name:$!");

	my $header_file_name = $file_name;
	$header_file_name =~ s/\./_/g;
	$header_file_name =~ s/-/_/g;

	printf DOT "digraph $header_file_name {\n";
	printf DOT "\tgraph [fontsize=10 size=\"180,180\"];\n";

	my $i;
	for $i ( 0 .. $#bb )
	{
		my $this_bb_ops = $bb[$i][3];
		my $successors  = $bb[$i][4];

		printf DOT "\tbb_0x%4.4x [shape=box];\n", $bb[$i][0];

		my $ops = "";
		my $op;
		foreach $op (@$this_bb_ops)
		{
			@$op[2] =~ s/FIXME/<font color="red">FIXME<\/font>/g;
			@$op[2] =~ s/(new CPU mode .*)/<font color="green">$1<\/font>/g;
			$ops = sprintf
				"%s<tr><td align=\"left\"><font face=\"Courier\">0x%4.4x:  %s</font></td><td align=\"left\"><font point-size=\"8\" face=\"Courier\">%s</font></td></tr>",
				$ops, @$op[0], @$op[2], @$op[1];
		}

		printf DOT "\tbb_0x%4.4x [label=<<table border=\"0\" cellborder=\"0\"><tr><td bgcolor=\"grey\" align=\"center\" colspan=\"2\">0x%4.4x   <font color=\"blue\" point-size=\"8\">%s</font></td></tr>%s</table>>];\n",
			$bb[$i][0], $bb[$i][0], $bb[$i][2], $ops;

		my $suc;
		foreach $suc (@$successors)
		{
			printf DOT "\tbb_0x%4.4x -> bb_0x%4.4x;\n", $bb[$i][0], $suc;
		}

	}
	printf DOT "}\n";
	close DOT;
}

sub main()
{
	$file_name = pop @ARGV;

	my $file_stat = stat($file_name) or die "can't stat $file_name: $!\n";

	$file_size = $file_stat->size;

	my $start_addr;
	if ($start_offset < 0)
	{
		$start_addr = $file_size + $start_offset;
	}else{
		$start_addr = $start_offset;
	}
	do_next_bb($start_addr, $x86_mode);

	my $extra;
	foreach $extra (@extra_bb)
	{
		do_next_bb(@$extra[0], @$extra[1]);
	}

	dump_dot_file();
}

main();
0;
