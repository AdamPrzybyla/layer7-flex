#
# Makefile for the Linux Traffic Control Unit.
#	flex -t cls_layer7.l |awk -v k="" '/#include <stdio.h>/ {k="//"} /#include <unistd.h>/ {k="//"} /typedef unsigned int yy_size_t/ {print $0; print "typedef  void FILE;";next} /extern FILE/ {k="//"} // {print k $0i;k=""}' >cls_layer7.c
#

cls_layer7.c:	cls_layer7.l
	flex -t cls_layer7.l |awk -v k="" '/#include <stdio.h>/ {k="//"} /#include <unistd.h>/ {k="//"} /typedef unsigned int yy_size_t/ {print $0; print "typedef  void FILE;";next} /extern FILE/ {k="//"} // {print k $0i;k=""}' >cls_layer7.c


O_TARGET := sched.o
#CFLAGS+= -I/usr/include
# EXTRA_CFLAGS+= -I/usr/include
obj-y	:= sch_generic.o 


obj-$(CONFIG_NET_SCHED)		+= sch_api.o sch_fifo.o
obj-$(CONFIG_NET_ESTIMATOR)	+= estimator.o
obj-$(CONFIG_NET_CLS)		+= cls_api.o
obj-$(CONFIG_NET_CLS_POLICE)	+= police.o
obj-$(CONFIG_NET_SCH_INGRESS)	+= sch_ingress.o 
obj-$(CONFIG_NET_SCH_CBQ)	+= sch_cbq.o
obj-$(CONFIG_NET_SCH_CSZ)	+= sch_csz.o
obj-$(CONFIG_NET_SCH_HPFQ)	+= sch_hpfq.o
obj-$(CONFIG_NET_SCH_HFSC)	+= sch_hfsc.o
obj-$(CONFIG_NET_SCH_HTB)	+= sch_htb.o
obj-$(CONFIG_NET_SCH_SFQ)	+= sch_sfq.o
obj-$(CONFIG_NET_SCH_RED)	+= sch_red.o
obj-$(CONFIG_NET_SCH_TBF)	+= sch_tbf.o
obj-$(CONFIG_NET_SCH_PRIO)	+= sch_prio.o
obj-$(CONFIG_NET_SCH_TEQL)	+= sch_teql.o
obj-$(CONFIG_NET_SCH_GRED)	+= sch_gred.o
obj-$(CONFIG_NET_SCH_DSMARK)	+= sch_dsmark.o
obj-$(CONFIG_NET_CLS_TCINDEX)	+= cls_tcindex.o
obj-$(CONFIG_NET_SCH_ATM)	+= sch_atm.o
obj-$(CONFIG_NET_CLS_U32)	+= cls_u32.o
obj-$(CONFIG_NET_CLS_RSVP)	+= cls_rsvp.o
obj-$(CONFIG_NET_CLS_RSVP6)	+= cls_rsvp6.o
obj-$(CONFIG_NET_CLS_ROUTE4)	+= cls_route.o
obj-$(CONFIG_NET_CLS_FW)	+= cls_fw.o
obj-$(CONFIG_NET_CLS_LAYER7)    += cls_layer7.o  #regexp/regexp.o regexp/regsub.o

include $(TOPDIR)/Rules.make
