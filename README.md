# atomun-core

[![License](http://img.shields.io/badge/license-Apache_2-red.svg)][Apache2.0]

[![Build Status](https://travis-ci.org/harningt/atomun-core.svg?branch=develop)](https://travis-ci.org/harningt/atomun-core)

[![codecov.io](https://codecov.io/github/harningt/atomun-core/coverage.svg?branch=develop)](https://codecov.io/github/harningt/atomun-core?branch=develop)

Enter [Atomun](https://github.com/harningt/atomun) - the Java Bitcoin utility library collection.

This library implements the base functionality required across the various
pieces of Atomun.

[![Join the chat at https://gitter.im/harningt/atomun](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/harningt/atomun?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)


## Versioning

This library will follow the guidelines set forth in [Semantic Versioning 2.0][SemVer2.0]

Public APIs not marked with @Beta are considered under the purview of the versioning rules.

@Beta items follow the attached documentation to the annotation, shortly put:

> Do not rely on this to exist in the future as it is not "API-frozen".
> It may change functionality or be removed in any future release.

Public APIs inside the us.eharning.atomun.core.internal namespace are not
considered 'public' per the versioning rules.

## License

This library is covered under the [Apache 2.0 license][Apache2.0] as indicated in the LICENSE file.

## Repository Details

The repository is managed using the Gitflow workflow. Note that any published
feature/* branches are subject to history modification, so beware working
off of those.

Non-annotated tags will be added in the form vMAJOR.MINOR.MICRO-dev to denote the
start of a new feature. This will guide the next release to be versioned as
vMAJOR.MINOR.MICRO. Without this, the next expected version would be a MICRO-change.

Signed and annotated tags will be added in the form vMAJOR.MINOR.MICRO to denote
releases.

## Maven Artifacts

Maven Group ID: us.eharning.atomun
Name: atomun-core

Signed SNAPSHOT artifacts are pushed per-commit by Travis-CI to the
Maven Central SNAPSHOT archive.

Signed release artifacts will be pushed directly to Maven Central.

<https://oss.sonatype.org/content/groups/public/>

## Release Signing

Releases will be signed by the following privately held GPG key. It doesn't
get published to Travis-CI.

    pub   2048R/F8908096 2014-10-29 [expires: 2016-10-28]
          Key fingerprint = B6CC 560D F1C0 991E 08AA  555A ED63 F369 F890 8096
    uid                  Thomas Harning Jr (CODE SIGNING KEY) <harningt@gmail.com>

See also <http://www.eharning.us/gpg/>

## Snapshot Signing

Snapshots will be signed by a key held by Travis-CI in their encrypted
data stores. I figured it would be better to sign the snapshots than not
have them signed at all, even if the specific key is less protected.

    pub   2048R/EF39E8D8 2015-03-10 [expires: 2016-03-09]
          Key fingerprint = FCA2 D4CC 9294 38B7 5B91  8D9E 6BF2 A2D1 EF39 E8D8
    uid                  Thomas Harning Jr (AUTOMATED CI CODESIGNER) <harningt@gmail.com>

## Tag Signing

Tags will be signed by the following privately held hardware-based GPG key.

    pub   3072R/B1DBAD54 2011-04-19
          Key fingerprint = 2F0A FF2E A8A0 1485 C95B  8650 F0A4 C0F7 B1DB AD54
    uid                  Thomas Harning Jr <harningt@gmail.com>

## Dependencies
### Build

 * Gradle

### Runtime

 * Guava 19.0

### Test

 * Spock Framework
 * caliper

### Quality

 * FindBugs
 * org.ajoberstar gradle defaults
    * many included things, such as license plugin

# Acknowledgements

## Other Builds

| Wercker | Shippable |
|---------|-----------|

[Apache2.0]: http://www.apache.org/licenses/LICENSE-2.0
[SemVer2.0]: http://semver.org/spec/v2.0.0.html
