#!/usr/bin/env bash
if [ "$TRAVIS_BRANCH" = 'master' ] && [ "$TRAVIS_PULL_REQUEST" == 'false' ]; then
    openssl aes-256-cbc -K $encrypted_746c7c18da90_key -iv $encrypted_746c7c18da90_iv -in cd/codeSingingKey.asc.enc -out cd/codeSigningKey.asc -d
    gpg --fast-import cd/codeSigningKey.asc
fi
