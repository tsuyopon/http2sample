#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([http2sample], [0.1], [hoge@example.com])

# Makefileを作成する際に作成する。引数にforeignを指定しないとNEWやChangelogなどのGNUプロジェクトで標準的に必要とされるファイルが必要となる。
AM_INIT_AUTOMAKE([foreign])

# ソースディレクトリの簡単なチェック。ソースパッケージに含まれるファイルの1つを指定する。
AC_CONFIG_SRCDIR([src/http2server.cc])
AC_CONFIG_HEADERS([configure.h])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([ssl], [SSL_get_client_random, SSL_SESSION_get_master_key, SSL_get_session, SSL_new, SSL_set_fd, SSL_accept, SSL_get0_alpn_selected, SSL_set_alpn_protos, SSL_set_tlsext_host_name, SSL_connect, SSL_read, SSL_shutdown, SSL_free, SSL_library_init, SSL_load_error_strings, TLSv1_2_method, SSL_CTX_new, SSL_CTX_use_certificate_file, SSL_CTX_use_PrivateKey_file, SSL_CTX_set_alpn_select_cb, SSL_CTX_free, ERR_free_strings])
AC_CHECK_LIB([crypto], [ERR_print_errors_fp])
AC_CHECK_LIB([m], [pow])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_INT8_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([bzero inet_ntoa memset pow socket])

# 最後に生成されるファイルがMakefileであることをautotoolsに知らせます。
AC_CONFIG_FILES([Makefile
                 src/Makefile])
# 実際のアウトプットを指定する
AC_OUTPUT
