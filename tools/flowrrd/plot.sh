#!/bin/sh

if [ "x$1" = "x" -o "x$2" = "x" ] ;then
	echo "Usage: plot.sh rrd image-dir" 1>&2
	exit 1
fi

RRDPATH="$1"
OUTPATH="$2"

for x in "flows" "packets" "bytes" ; do
	[ "x$x" = "xflows" ] && T="Flows"
	[ "x$x" = "xpackets" ] && T="Packets"
	[ "x$x" = "xbytes" ] && T="Bytes"

	for y in "day" "week" "month" "year" ; do 
		[ "x$y" = "xday" ] && S="end-192000s"
		[ "x$y" = "xweek" ] && S="end-1152000s"
		[ "x$y" = "xmonth" ] && S="end-4608000s"
		[ "x$y" = "xyear" ] && S="end-55296000s"

		echo -n "Graphing ${x}-${y}.png: "	
		rrdtool graph ${OUTPATH}/${x}-${y}.png \
			--imgformat PNG				\
			--vertical-label "${T} per second"	\
			--end now --start ${S}			\
			--width 640 --height 200		\
			DEF:other=${RRDPATH}:other_${x}:AVERAGE	\
			DEF:icmp=${RRDPATH}:icmp_${x}:AVERAGE	\
			DEF:gre=${RRDPATH}:gre_${x}:AVERAGE	\
			DEF:esp=${RRDPATH}:esp_${x}:AVERAGE	\
			DEF:tcp=${RRDPATH}:tcp_${x}:AVERAGE	\
			DEF:udp=${RRDPATH}:udp_${x}:AVERAGE	\
			\
			COMMENT:"      "			\
			AREA:other#cfa941:"Other    "		\
			COMMENT:" Last: "			\
			GPRINT:other:LAST:"%6.2lf%s"		\
			COMMENT:" Avg: "			\
			GPRINT:other:AVERAGE:"%6.2lf%s"		\
			COMMENT:" Min: "			\
			GPRINT:other:MIN:"%6.2lf%s"		\
			COMMENT:" Max: "			\
			GPRINT:other:MAX:"%6.2lf%s\n"		\
			\
			COMMENT:"      "			\
			STACK:icmp#cf41cd:"ICMP     "		\
			COMMENT:" Last: "			\
			GPRINT:icmp:LAST:"%6.2lf%s"		\
			COMMENT:" Avg: "			\
			GPRINT:icmp:AVERAGE:"%6.2lf%s"		\
			COMMENT:" Min: "			\
			GPRINT:icmp:MIN:"%6.2lf%s"		\
			COMMENT:" Max: "			\
			GPRINT:icmp:MAX:"%6.2lf%s\n"		\
			\
			COMMENT:"      "			\
			STACK:gre#d0d21c:"GRE      "		\
			COMMENT:" Last: "			\
			GPRINT:gre:LAST:"%6.2lf%s"		\
			COMMENT:" Avg: "			\
			GPRINT:gre:AVERAGE:"%6.2lf%s"		\
			COMMENT:" Min: "			\
			GPRINT:gre:MIN:"%6.2lf%s"		\
			COMMENT:" Max: "			\
			GPRINT:gre:MAX:"%6.2lf%s\n"		\
			\
			COMMENT:"      "			\
			STACK:esp#d54f4f:"ESP IPsec"		\
			COMMENT:" Last: "			\
			GPRINT:esp:LAST:"%6.2lf%s"		\
			COMMENT:" Avg: "			\
			GPRINT:esp:AVERAGE:"%6.2lf%s"		\
			COMMENT:" Min: "			\
			GPRINT:esp:MIN:"%6.2lf%s"		\
			COMMENT:" Max: "			\
			GPRINT:esp:MAX:"%6.2lf%s\n"		\
			\
			COMMENT:"      "			\
			STACK:tcp#6e5bd7:"TCP      "		\
			COMMENT:" Last: "			\
			GPRINT:tcp:LAST:"%6.2lf%s"		\
			COMMENT:" Avg: "			\
			GPRINT:tcp:AVERAGE:"%6.2lf%s"		\
			COMMENT:" Min: "			\
			GPRINT:tcp:MIN:"%6.2lf%s"		\
			COMMENT:" Max: "			\
			GPRINT:tcp:MAX:"%6.2lf%s\n"		\
			\
			COMMENT:"      "			\
			STACK:udp#5eb15c:"UDP      "		\
			COMMENT:" Last: "			\
			GPRINT:udp:LAST:"%6.2lf%s"		\
			COMMENT:" Avg: "			\
			GPRINT:udp:AVERAGE:"%6.2lf%s"		\
			COMMENT:" Min: "			\
			GPRINT:udp:MIN:"%6.2lf%s"		\
			COMMENT:" Max: "			\
			GPRINT:udp:MAX:"%6.2lf%s\n"
	done
done
