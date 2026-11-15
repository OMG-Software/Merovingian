DISTNAME=       merovingian-1.0.2
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
DEPENDS+=       png>=1.6:../../graphics/png
DEPENDS+=       libjpeg-turbo>=2:../../graphics/libjpeg-turbo

MESON_ARGS+=    --wrap-mode=forcefallback
MESON_ARGS+=    -Dhardening=true

# Create merovingian group and system user during package install.
PKG_GROUPS=         merovingian
PKG_USERS=          merovingian
PKG_GECOS.merovingian=  Merovingian homeserver
PKG_SHELL.merovingian=  /sbin/nologin
PKG_HOME.merovingian=   /var/db/merovingian
PKG_GROUPS_VARS=    merovingian:PKG_GROUPS
PKG_USERS_VARS=     merovingian:PKG_USERS

# Install the rc.d control script via pkgsrc's RCD_SCRIPTS mechanism.
RCD_SCRIPTS=        merovingian

# The sample config is the BSD example, never the Linux one, with its
# configuration directory filled in; CONF_FILES copies it to the live path only
# when no config is there yet (ADR-0738).
SUBST_CLASSES+=             sysconfdir
SUBST_STAGE.sysconfdir=     pre-configure
SUBST_MESSAGE.sysconfdir=   Filling in the configuration directory.
SUBST_FILES.sysconfdir=     config/merovingian.conf.bsd.example
SUBST_SED.sysconfdir=       -e 's,@SYSCONFDIR@,${PKG_SYSCONFDIR},g'

EGDIR=                      ${PREFIX}/share/examples/merovingian
INSTALLATION_DIRS+=         ${EGDIR}
MAKE_DIRS+=                 ${PKG_SYSCONFDIR}/merovingian
CONF_FILES=                 ${EGDIR}/merovingian.conf.sample \
                            ${PKG_SYSCONFDIR}/merovingian/merovingian.conf

post-install:
	${INSTALL_DATA} ${WRKSRC}/config/merovingian.conf.bsd.example \
	    ${DESTDIR}${EGDIR}/merovingian.conf.sample

.include "../../devel/meson/build.mk"
# OpenSSL comes through buildlink3, which picks NetBSD's base OpenSSL or the
# pkgsrc package the same way curl and postgresql17-client were built, and adds
# the dependency itself. An explicit DEPENDS on pkgsrc openssl would link a
# second OpenSSL alongside the one those libraries load.
.include "../../security/openssl/buildlink3.mk"
.include "../../mk/bsd.pkg.mk"
