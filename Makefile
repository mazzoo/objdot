
TARGET=coreboot.rom

#DOT=/cygdrive/c/Programme/Graphviz2.26.3/bin/dot.exe
DOT=dot
PS2PDF=epstopdf

all:$(TARGET).ps $(TARGET).pdf $(TARGET).png

$(TARGET).pdf:$(TARGET).ps
	$(PS2PDF) --outfile=$@ $^

$(TARGET).ps:$(TARGET).dot
	$(DOT) -Tps2 -o $@ $^

$(TARGET).png:$(TARGET).dot
	$(DOT) -Tpng -o $@ $^

$(TARGET).dot:objdot.pl $(TARGET)
	./objdot.pl $(TARGET)

clean:
	rm -f $(TARGET).ps $(TARGET).pdf $(TARGET).png $(TARGET).dot
