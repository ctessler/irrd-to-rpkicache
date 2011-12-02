#!/bin/bash

#
# The root checkout of http://subvert-rpki.hactrn.net/trunk
#
RIPE_PATH=/home/ctessler/vc/ripe-trunk

#
# Where openssl was built
#
OPENSSL_PATH=/home/ctessler/vc/git/openssl-1.0.0e

#
# Where RPKIC tools are
#
RPKIC_PATH=/home/ctessler/vc/git/rpki/bin

#
# ----------------------------------------------------------------------
#
ripe=${RIPE_PATH}/utils/print_roa
openssl=${OPENSSL_PATH}/apps

PATH=${ripe}:${openssl}:${RPKIC_PATH}:${PATH}
export PATH

rpki-fetch.pl
rpki-vdate.pl
rpki-import.pl
