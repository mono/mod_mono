CSC=mcs
CSCFLAGS+= /debug+ /debug:full /nologo

# 
REFERENCES= System.Web
REFS= $(addsuffix .dll, $(addprefix /r:, $(REFERENCES)))
SOURCES = ApacheApplicationHost.cs \
	  ApacheWorkerRequest.cs \
	  MonoWorkerRequest.cs \
	  IApplicationHost.cs \
	  Request.cs

all: ModMono.dll

ModMono.dll: $(SOURCES)
	$(CSC) $(CSCFLAGS) $(REFS) /target:library /out:$@ $^

clean:
	rm -f ModMono.dll *~ *.pdb *.dbg


