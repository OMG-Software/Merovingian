DISTNAME=       merovingian-0.1.65
CATEGORIES=    net
MASTER_SITES=   ${MASTER_SITE_GITHUB:=OMG-Software/}
GITHUB_PROJECT= Merovingian

MAINTAINER=     maintainers@example.invalid
HOMEPAGE=       https://github.com/OMG-Software/Merovingian
COMMENT=        Secure Matrix Protocol homeserver
LICENSE=        gnu-gpl-v3

USE_LANGUAGES=  c c++
USE_TOOLS+=     pkg-config perl bison flex gmake

DEPENDS+=       libsodium>=1.0.18:../../security/libsodium
DEPENDS+=       postgresql17-client>=17:../../databases/postgresql17-client
DEPENDS+=       curl>=8:../../www/curl

MESON_ARGS+=    --wrap-mode=forcefallback
MESON_ARGS+=    -Dhardening=true

.include "../../devel/meson/build.mk"
.include "../../security/openssl/buildlink3.mk"
.include "../../mk/bsd.pkg.mk"
