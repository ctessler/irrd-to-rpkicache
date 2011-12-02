This directory includes the original irrd source and patches that
were used to communicate with the rpki-checkd.pl RPKI cache server.

The IRRd version was 2.3.10

Files: 
    0001-Communicates-with-the-RPKI-Cache.patch
    irrd2.3.10.tgz

To apply the patches:

    tar -zxvf irrd2.3.10.tgz 
    cd irrd2.3.10
    patch -p1 < *.patch
