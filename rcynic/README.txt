This directory includes the original rcynic source and patches that
were used to add the -e option to print_roa. The -e option extracts
the EE certificate from the ROA so that it can be validated using
openssl. 

The rcynic source version was http://subvert-rpki.hactrn.net@4068

0001-Added-e-option-for-dumping-the-EE-certificate.patch
0002-Small-cleanup-from-e-option.patch

To apply the patches:

    tar -zxvf rcynic-4068.tar.gz
    cd rcynic-4068
    patch -p1 < *.patch
