NAME = ClaimTransformer
VERSION = 1.4
MONOCC = gmcs
MONO   = mono
TARGET = $(NAME).exe
DLL = $(NAME).dll
LIBDIR = ../libs
LIBS =	$(LIBDIR)/System.Web.Security.SingleSignOn.ClaimTransforms.dll,$(LIBDIR)/System.Web.Security.SingleSignOn.dll,$(LIBDIR)/System.Web.Security.SingleSignOn.Resources.dll,System.Configuration.dll 
DIST = $(NAME)-$(VERSION).zip
DISTFILES = INSTALL ChangeLog web.config $(DLL)

MONO_FLAGS = MONO_PATH=$(LIBDIR)
#MONO_FLAGS += MONO_LOG_LEVEL=debug

PROGS = $(TARGET) $(DLL)

all: $(PROGS)

%.dll: %.cs
	$(MONOCC) -r:$(LIBS) -target:library $<

%.exe: %.cs
	$(MONOCC) -r:$(LIBS) $<

clean:
	rm -f $(PROGS) *.zip

run: $(PROGS)
	$(MONO_FLAGS) $(MONO) $(TARGET)

web.config: ClaimTransformer.exe.config
	cp ClaimTransformer.exe.config web.config

$(DIST): $(DISTFILES)
	zip $@ $(DISTFILES)
	rm web.config

dist: $(DIST)

