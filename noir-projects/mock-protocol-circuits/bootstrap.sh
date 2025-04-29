#!/usr/bin/env bash
source $(git rev-parse --show-toplevel)/bberg/ci3/source

NO_CD=1 ../noir-protocol-circuits/bootstrap.sh $@