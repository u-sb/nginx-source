# A build system class for handling nginx modules.
#
# Copyright: © 2022 Miao Wang
# License: MIT

package Debian::Debhelper::Buildsystem::nginx_mod;

use strict;
use warnings;
use Debian::Debhelper::Dh_Lib qw(error doit);
use File::Spec;
use parent qw(Debian::Debhelper::Buildsystem::makefile);
use Config;

sub DESCRIPTION {
	"Nginx Module (config)"
}

sub check_auto_buildable {
	my ($this, $step) = @_;

	return 1 if -e $this->get_sourcepath("config");
}

sub _NGINX_SRC_DIR {
    "/usr/share/nginx/src"
}

sub new {
	my $class=shift;
	my $this= $class->SUPER::new(@_);
	$this->prefer_out_of_source_building(@_);
	return $this;
}

sub configure {
	my $this=shift;

    doit({
        "chdir" => $this->_NGINX_SRC_DIR,
        "update_env" => {
            "src_dir" => $this->get_sourcedir,
            "bld_dir" => $this->get_builddir,
            "pwd_dir" => $this->{cwd},
        },
    }, "bash", "-c", '. ./conf_flags
    ./configure \\
        --with-cc-opt="$(cd "$pwd_dir/$src_dir"; dpkg-buildflags --get CFLAGS) -fPIC $(cd "$pwd_dir/$src_dir"; dpkg-buildflags --get CPPFLAGS)" \\
        --with-ld-opt="$(cd "$pwd_dir/$src_dir"; dpkg-buildflags --get LDFLAGS) -fPIC" \\
        "${NGX_CONF_FLAGS[@]}" \\
        --add-dynamic-module="$pwd_dir/$src_dir" \\
        --builddir="$pwd_dir/$bld_dir" \\
        "$@"', "dummy", @_);
}

sub build {
	my $this=shift;
    
    $this->do_make("-f", File::Spec->catfile($this->{cwd}, $this->get_buildpath("Makefile")), "-C", $this->_NGINX_SRC_DIR, "modules");
}

sub test {
    my $this=shift;
    $this->doit_in_builddir("bash", "-e", "-o", "pipefail", "-c", '
        tmp_conf=$(mktemp -p .)
        for pre_dep in "$@"; do
          echo "load_module modules/$pre_dep;" >> "$tmp_conf"
        done
        for i in *.so; do
          echo "load_module $PWD/$i;" >> "$tmp_conf"
        done
        echo "events{}" >> "$tmp_conf"
        nginx -g "error_log /dev/null; pid /dev/null;"  -t -q -c "$PWD/$tmp_conf"
        rm -f "$tmp_conf"
    ', "dummy", @_);
}

sub install {
	my $this=shift;
	my $destdir=shift;

    $this->doit_in_builddir("bash", "-e", "-o", "pipefail", "-c", '
        destdir=$1
        mkdir -p "$destdir/usr/lib/nginx/modules"
        for i in *.so; do
          cp "$i" "$destdir/usr/lib/nginx/modules/"
        done
    ', "dummy", $destdir);
}

sub clean {
    my $this=shift;
    $this->rmdir_builddir();
}

1
