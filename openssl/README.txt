This directory includes the openssl distribution tarball and required
patches for the arbitrary length x509 certificate chain verifications.

openssl-1.0.0e.tar.gz	original source
verify.c.00.diff	patch

To apply the patch

    tar -zxvf openssl-1.0.0e.tar.gz
    cd openssl-1.0.0e
    patch -p1 < verify.c.00.diff
