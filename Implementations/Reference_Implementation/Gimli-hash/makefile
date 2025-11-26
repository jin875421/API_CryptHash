# Makefile
SUBDIR := .
SUBDIR += ./hash

INCS := $(foreach dir,$(SUBDIR),-I$(dir))
SRCS := $(foreach dir,$(SUBDIR),$(wildcard $(dir)/*.c))

KAT_CryptHash : $(SRCS)
	gcc $(INCS) $(SRCS) -o KAT_CryptHash