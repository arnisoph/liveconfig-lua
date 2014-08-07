--  _    _          ___           __ _     (R)
-- | |  (_)_ _____ / __|___ _ _  / _(_)__ _
-- | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
-- |____|_|\_/\___|\___\___/_||_|_| |_\__, |
--                                    |___/
-- Copyright (c) 2009-2012 Keppler IT GmbH.
-- ---------------------------------------------------------------------------
-- common/lua/apache.lua
-- Lua module to manage Apache httpd web server
-- $Id: apache.lua 2849 2014-04-24 17:05:03Z kk $
-- ---------------------------------------------------------------------------
-- This is the "driver" module for Apache httpd web server.
-- It must be loaded by the command
--   LC.web.load("apache")
-- Usually, this should happen at liveconfig.lua (or, if you have a customized
-- module, at custom.lua)
-- ---------------------------------------------------------------------------

-- Imported functions
local LC = LC
local LCS = LCS -- import liveconfig global storage
local assert = assert
local type = type
local io = io
local os = os
local ipairs = ipairs
local pairs = pairs
local string = string
local table = table     -- for table.sort
local tonumber = tonumber

-- Module declaration
module("apache")

-- Set configuration mode for virtual hosts
-- Possible values:
-- 'virtualhost': generate a <VirtualHost> section for each different
--                domain configuration (better compatibility)
-- 'rewrite': generate only one <VirtualHost> per subscription, configure all
--            additional domains using RewriteRules (better performance when
--            managing >1000 subscriptions on one host)
-- Default is "virtualhost", can be overridden in "custom.lua"
if CONFIGMODE == nil then
  CONFIGMODE = 'virtualhost'
end

-- Exported functions
--   detect()
--   install()
--   uninstall()
--   configure()
--   configureVHost()
--   reload()
--   restart()
--   deleteAccount()

-- ---------------------------------------------------------------------------
-- escape()
--
-- Escape quotes in a string to make them safe for config files
-- ---------------------------------------------------------------------------
local function escape(s)
  return string.gsub(s, '"', '\\"')
end

-- ---------------------------------------------------------------------------
-- getBinaryVersion()
--
-- Return the binary version number from Apache httpd
-- ---------------------------------------------------------------------------
local function getBinaryVersion(bin)
  local handle = io.popen(bin .. " -v", "r")
  local ret = handle:read("*a")
  handle:close()
  local v = string.match(ret, "Apache/(%d+%.%d+[%.%d+]*)")
  return v
end

-- ---------------------------------------------------------------------------
-- check_sni()
--
-- Check list of files if SNI seems to be supported
-- ---------------------------------------------------------------------------
local function check_sni(files)
  if type(files) == "table" then
    -- check list of files
    local i
    for i in pairs(files) do
      if LC.fs.is_file(files[i]) then
        local fh = assert(io.popen('grep -cU TLS_SNI "' .. files[i] .. '"', 'r'))
        local s = assert(fh:read('*a'))
        fh:close()
        if string.find(s, '^1') ~= nil then
          return true
        end
      end
    end
  else
    -- check single file name
    if LC.fs.is_file(files) then
      local fh = assert(io.popen('grep -cU TLS_SNI "' .. files .. '"', 'r'))
      local s = assert(fh:read('*a'))
      fh:close()
      if string.find(s, '^1') ~= nil then
        return true
      end
    end
  end
  return false
end

-- ---------------------------------------------------------------------------
-- check_modules()
--
-- Get list of enabled Apache modules
-- ---------------------------------------------------------------------------
local function check_modules(apachectl, args)
  if not LC.fs.is_file(apachectl) then return nil end
  local fh = assert(io.popen(apachectl .. " " .. args .. " 2>&1", "r"))
  local list = {}
  while true do
    local line = fh:read()
    if line == nil then break end
    local m = string.match(line, "([%w_]+)_module")
    if m then
      list[#list+1] = m
    end
  end
  fh:close()
  return list
end

-- ---------------------------------------------------------------------------
-- detect()
--
-- Detect if an Apache httpd is installed. If yes, return a table containing
-- all relevant informations:
--   type          => "apache"
--   binname       => file name of the Apache httpd binary (eg. "/usr/sbin/apache2")
--   binversion    => binary version (eg. "2.2.3")
--   pkgname       => name of the package (see below)
--   pkgversion    => package version number (eg. "2.2.3-4+etch11")
--   configpath    => Main configuration path for Apache
--   configfile    => LiveConfigs' configuration file (snippet)
--   statusfile    => LiveConfigs' status file (containing config version etc.)
--   defaultlog    => Default log file (for default and unknown/unconfigured vhosts)
--   start_cmd     => command to start Apache httpd
--   stop_cmd      => command to stop Apache httpd
--   reload_cmd    => command to re-load configuration
--   restart_cmd   => command to re-start Apache process
--   available_dir => path for all available vhost configuration files
--   enabled_dir   => path for enabled vhost configuration files
--   enable_cmd    => command to enable a vhost configuration file (eg. "/usr/sbin/a2ensite")
--   disable_cmd   => command to disable a vhost configuration file (eg. "/usr/sbin/a2dissite")
--   httpd_user    => user running Apache httpd
--   httpd_group   => group running Apache httpd
--   has_sni       => true if Apache supports SNI
--
-- If pkgversion is 'nil', then Apache httpd was most propably not installed
-- as native distribution package, but compiled/installed manually.
-- ---------------------------------------------------------------------------
function detect()

  -- first check for distribution-specific packages
  if LC.distribution.family == "Debian" then
    -- Debian/Ubuntu
    -- Package is named "apache2", but is only a meta-package; the real
    -- installation is made via "apache2-mpm-[...]", so we look for a list
    -- of packages.
    local pkg, v = LC.distribution.hasPackage( 'apache2', 'apache2-mpm-prefork', 'apache2-mpm-worker', 'apache2-mpm-event', 'apache2-mpm-perchild', 'apache2-mpm-itk')
    if pkg ~= nil then
      LC.log.print(LC.log.DEBUG, "Found package '", pkg, "' (Version ", v, ")")
      local bin = "/usr/sbin/apache2"
      -- get binary version
      local bv = getBinaryVersion(bin)
      LC.log.print(LC.log.DEBUG, "binver ", bv)
      if bv ~= nil then
        -- ok, we have all informations. return data table:
        local data = {
            ["type"]          = "apache",
            ["binname"]       = bin,
            ["binversion"]    = bv,
            ["pkgname"]       = pkg,
            ["pkgversion"]    = v,
            ["configpath"]    = "/etc/apache2",
            ["configfile"]    = "/etc/apache2/conf.d/liveconfig",
            ["statusfile"]    = "/etc/apache2/liveconfig.status",
            ["defaultlog"]    = "/var/log/apache2/default_vhost.log",
            ["start_cmd"]     = "/etc/init.d/apache2 start",
            ["stop_cmd"]      = "/etc/init.d/apache2 stop",
            ["reload_cmd"]    = "/etc/init.d/apache2 reload",
            ["restart_cmd"]   = "/etc/init.d/apache2 restart",
            ["available_dir"] = "/etc/apache2/sites-available",
            ["enabled_dir"]   = "/etc/apache2/sites-enabled",
            ["enable_cmd"]    = "/usr/sbin/a2ensite",
            ["disable_cmd"]   = "/usr/sbin/a2dissite",
            ["httpd_user"]    = "www-data",
            ["httpd_group"]   = "www-data",
            ["has_sni"]       = check_sni("/usr/lib/apache2/modules/mod_ssl.so"),
            ["ssl_cert_dir"]  = "/etc/ssl/certs",
            ["ssl_key_dir"]   = "/etc/ssl/private",
            ["ssl_key_user"]  = "root",
            ["ssl_key_group"] = "ssl-cert",
            ["ssl_key_mode"]  = "0640",
            ["htdocs_path"]   = LC.web.HTDOCS_PATH,
            ["modules"]       = check_modules("/usr/sbin/apache2ctl", "-M"),
        }
        if LC.fs.is_dir("/etc/apache2/conf-available") and LC.fs.is_dir("/etc/apache2/conf-enabled") then
          -- new config layout (Ubuntu 13.10+)
          data["configfile"] = "/etc/apache2/conf-available/liveconfig.conf"
        end
        return data
      end
      -- else: fall trough, to check for custom Apache installation
      LC.log.print(LC.log.DEBUG, "LC.apache.detect(): Found Apache package '", pkg, "', but no binary at ", bin)
    end
  
  elseif LC.distribution.family == "Gentoo" then
    -- Gentoo
    local pkg, v = LC.distribution.hasPackage('apache')

    if pkg ~= nil then
      LC.log.print(LC.log.DEBUG, "Found package '", pkg, "' (Version ", v, ")")
      local bin = "/usr/sbin/apache2"
      local bv = getBinaryVersion(bin)
      LC.log.print(LC.log.DEBUG, "binver ", bv)
      if bv ~= nil then
        local data = {
            ["type"]          = "apache",
            ["binname"]       = bin,
            ["binversion"]    = bv,
            ["pkgname"]       = pkg,
            ["pkgversion"]    = v,
            ["configpath"]    = "/etc/apache2",
            ["configfile"]    = "/etc/apache2/modules.d/99_liveconfig.conf",
            ["statusfile"]    = "/etc/apache2/liveconfig.status",
            ["defaultlog"]    = "/var/log/apache2/default_vhost.log",
            ["start_cmd"]     = "/etc/init.d/apache2 start",
            ["stop_cmd"]      = "/etc/init.d/apache2 stop",
            ["reload_cmd"]    = "/etc/init.d/apache2 reload",
            ["restart_cmd"]   = "/etc/init.d/apache2 restart",
            ["available_dir"] = nil,
            ["enabled_dir"]   = "/etc/apache2/vhosts.d",
            ["enable_cmd"]    = nil,
            ["disable_cmd"]   = nil,
            ["httpd_user"]    = "apache",
            ["httpd_group"]   = "apache",
            ["has_sni"]       = check_sni("/usr/lib/apache2/modules/mod_ssl.so"),
            ["ssl_cert_dir"]  = "/etc/ssl/apache2",
            ["ssl_key_dir"]   = "/etc/ssl/apache2",
            ["ssl_key_user"]  = "root",
            ["ssl_key_group"] = "root",
            ["ssl_key_mode"]  = "0600",
            ["htdocs_path"]   = LC.web.HTDOCS_PATH,
            ["modules"]       = check_modules("/etc/init.d/apache2", "modules"),
        }
        return data
      end
      -- else: fall trough, to check for custom Apache installation
      LC.log.print(LC.log.DEBUG, "LC.apache.detect(): Found Apache package '", pkg, "', but no binary at ", bin)
    end

  elseif LC.distribution.family == "RedHat" then
    -- CentOS
    local pkg, v = LC.distribution.hasPackage('httpd')
    if pkg ~= nil then
      LC.log.print(LC.log.DEBUG, "Found package '", pkg, "' (Version ", v, ")")
      local bin = "/usr/sbin/httpd"
      local bv = getBinaryVersion(bin)
      LC.log.print(LC.log.DEBUG, "binver ", bv)
      if bv ~= nil then
        local data = {
            ["type"]          = "apache",
            ["binname"]       = bin,
            ["binversion"]    = bv,
            ["pkgname"]       = pkg,
            ["pkgversion"]    = v,
            ["configpath"]    = "/etc/httpd",
            ["configfile"]    = "/etc/httpd/conf.d/99_liveconfig.conf",
            ["statusfile"]    = "/etc/httpd/liveconfig.status",
            ["defaultlog"]    = "/var/log/httpd/default_vhost.log",
            ["start_cmd"]     = "/sbin/service httpd start",
            ["stop_cmd"]      = "/sbin/service httpd stop",
            ["reload_cmd"]    = "/sbin/service httpd reload",
            ["restart_cmd"]   = "/sbin/service httpd graceful",
            ["available_dir"] = nil,
            ["enabled_dir"]   = "/etc/httpd/vhosts.d",
            ["enable_cmd"]    = nil,
            ["disable_cmd"]   = nil,
            ["httpd_user"]    = "apache",
            ["httpd_group"]   = "apache",
            ["has_sni"]       = check_sni("/usr/lib64/httpd/modules/mod_ssl.so"),
            ["ssl_cert_dir"]  = "/etc/pki/tls/certs",
            ["ssl_key_dir"]   = "/etc/pki/tls/private",
            ["ssl_key_user"]  = "root",
            ["ssl_key_group"] = "root",
            ["ssl_key_mode"]  = "0600",
            ["htdocs_path"]   = LC.web.HTDOCS_PATH,
            ["modules"]       = check_modules("/usr/sbin/apachectl", "-M"),
        }
        return data
      end
    -- else: fall trough, to check for custom Apache installation
      LC.log.print(LC.log.ERROR, "LC.apache.detect(): Found Apache package '", pkg, "', but no binary at ", bin)
    end
  elseif LC.distribution.family == "SUSE" then
    -- OpenSUSE
    local pkg, v = LC.distribution.hasPackage('apache2')
    if pkg ~= nil then
      LC.log.print(LC.log.DEBUG, "Found package '", pkg, "' (Version ", v, ")")
      local bin = "/usr/sbin/httpd2"
      local bv = getBinaryVersion(bin)
      LC.log.print(LC.log.DEBUG, "binver ", bv)
      if bv ~= nil then
        local data = {
            ["type"]          = "apache",
            ["binname"]       = bin,
            ["binversion"]    = bv,
            ["pkgname"]       = pkg,
            ["pkgversion"]    = v,
            ["configpath"]    = "/etc/apache2",
            ["configfile"]    = "/etc/apache2/conf.d/liveconfig.conf",
            ["statusfile"]    = "/etc/apache2/liveconfig.status",
            ["defaultlog"]    = "/var/log/apache2/default_vhost.log",
            ["start_cmd"]     = "/usr/sbin/rcapache2 start",
            ["stop_cmd"]      = "/usr/sbin/rcapache2 stop",
            ["reload_cmd"]    = "/usr/sbin/rcapache2 reload",
            ["restart_cmd"]   = "/usr/sbin/rcapache2 restart",
            ["available_dir"] = nil,
            ["enabled_dir"]   = "/etc/apache2/vhosts.d",
            ["enable_cmd"]    = nil,
            ["disable_cmd"]   = nil,
            ["httpd_user"]    = "wwwrun",
            ["httpd_group"]   = "www",
            ["has_sni"]       = check_sni("/usr/lib64/apache2-prefork/mod_ssl.so"),
            ["ssl_cert_dir"]  = "/etc/apache2/ssl.crt",
            ["ssl_key_dir"]   = "/etc/apache2/ssl.key",
            ["ssl_key_user"]  = "root",
            ["ssl_key_group"] = "root",
            ["ssl_key_mode"]  = "0600",
            ["htdocs_path"]   = LC.web.HTDOCS_PATH,
            ["modules"]       = check_modules("/usr/sbin/apache2ctl", "-M"),
        }
        return data
      end
    -- else: fall trough, to check for custom Apache installation
      LC.log.print(LC.log.ERROR, "LC.apache.detect(): Found Apache package '", pkg, "', but no binary at ", bin)
    end
  elseif LC.distribution.family == "BSD" then
    -- FreeBSD
    local pkg, v = LC.distribution.hasPackage('apache-2.2')
    if pkg ~= nil then
      LC.log.print(LC.log.DEBUG, "Found package '", pkg, "' (Version ", v, ")")
      local bin = "/usr/local/sbin/httpd"
      local bv = getBinaryVersion(bin)
      LC.log.print(LC.log.DEBUG, "binver ", bv)
      if bv ~= nil then
        local data = {
            ["type"]          = "apache",
            ["binname"]       = bin,
            ["binversion"]    = bv,
            ["pkgname"]       = pkg,
            ["pkgversion"]    = v,
            -- Baustelle
            ["configpath"]    = "/usr/local/etc/apache22",
            ["configfile"]    = "/usr/local/etc/apache22/extra/liveconfig.conf",
            ["statusfile"]    = "/usr/local/etc/apache22/liveconfig.status",
            ["defaultlog"]    = "/var/log/httpd-access.log",
            ["start_cmd"]     = "/usr/local/etc/rc.d/apache22 start",
            ["stop_cmd"]      = "/usr/local/etc/rc.d/apache22 stop",
            ["reload_cmd"]    = "/usr/local/etc/rc.d/apache22 reload",
            ["restart_cmd"]   = "/usr/local/etc/rc.d/apache22 graceful",
            ["available_dir"] = nil,
            ["enabled_dir"]   = "/usr/local/etc/apache22/vhosts.d",
            ["enable_cmd"]    = nil,
            ["disable_cmd"]   = nil,
            ["httpd_user"]    = "www",
            ["httpd_group"]   = "www",
            ["has_sni"]       = check_sni("/usr/local/libexec/apache22/mod_ssl.so"),
            ["htdocs_path"]   = LC.web.HTDOCS_PATH,
            ["modules"]       = check_modules("/usr/local/sbin/apachectl", "-M"),
        }
        return data
      end
    -- else: fall trough, to check for custom Apache installation
      LC.log.print(LC.log.ERROR, "LC.apache.detect(): Found Apache package '", pkg, "', but no binary at ", bin)
    end
  end  
end

-- ---------------------------------------------------------------------------
-- install(cfg, opts)
--
-- Install LiveConfig configuration files for Apache httpd
-- ---------------------------------------------------------------------------
function install(cfg, opts)
  LC.log.print(LC.log.INFO, "Activating management of Apache httpd")

  local fh, status, msg
  local configpath = cfg["configpath"]
  local configfile = cfg["configfile"]
  local statusfile = cfg["statusfile"]
  local vhostpath  = cfg["available_dir"] or cfg["enabled_dir"]
  local vhostfile  -- set below (distribution-specific)

  if opts and opts.prefix then
    -- use prefix (for testing etc.)
    configpath = opts.prefix .. configpath
    configfile = opts.prefix .. configfile
    statusfile = opts.prefix .. statusfile
    vhostpath  = opts.prefix .. vhostpath
  end

  if LC.distribution.family == "RedHat" then

    -- create httpd.conf for RedHat
    local apachecfgfile = configpath .. "/conf/httpd.conf"

    -- backup old apachecfgfile
    if LC.fs.is_file(apachecfgfile) and not LC.fs.is_file(apachecfgfile .. ".lcbak") then
      LC.fs.rename(apachecfgfile, apachecfgfile .. ".lcbak")
    end

    -- backup old ssl.conf
    if LC.fs.is_file(configpath .. "/conf.d/ssl.conf") then
      LC.fs.rename(configpath .. "/conf.d/ssl.conf", configpath .. "/conf.d/ssl.conf.lcbak")
    end

    fh, msg = io.open(apachecfgfile, "w")
    if fh == nil then
      LC.log.print(LC.log.ERR, "Can't open '", apachecfgfile, "' for writing: ", msg)
      return false, "Can't open '" .. apachecfgfile .. "' for writing: " .. msg
    end

    -- write header
    LC.liveconfig.writeHeader(fh)

    fh:write( [[

ServerTokens Prod
ServerRoot "/etc/httpd"
PidFile run/httpd.pid
Timeout 60
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 15
<IfModule prefork.c>
StartServers       8
MinSpareServers    5
MaxSpareServers   20
ServerLimit      256
MaxClients       256
MaxRequestsPerChild  4000
</IfModule>

<IfModule worker.c>
StartServers         2
MaxClients         150
MinSpareThreads     25
MaxSpareThreads     75 
ThreadsPerChild     25
MaxRequestsPerChild  0
</IfModule>

LoadModule auth_basic_module modules/mod_auth_basic.so
LoadModule auth_digest_module modules/mod_auth_digest.so
LoadModule authn_file_module modules/mod_authn_file.so
LoadModule authn_alias_module modules/mod_authn_alias.so
LoadModule authn_anon_module modules/mod_authn_anon.so
LoadModule authn_dbm_module modules/mod_authn_dbm.so
LoadModule authn_default_module modules/mod_authn_default.so
LoadModule authz_host_module modules/mod_authz_host.so
LoadModule authz_user_module modules/mod_authz_user.so
LoadModule authz_owner_module modules/mod_authz_owner.so
LoadModule authz_groupfile_module modules/mod_authz_groupfile.so
LoadModule authz_dbm_module modules/mod_authz_dbm.so
LoadModule authz_default_module modules/mod_authz_default.so
LoadModule ldap_module modules/mod_ldap.so
LoadModule authnz_ldap_module modules/mod_authnz_ldap.so
LoadModule include_module modules/mod_include.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule logio_module modules/mod_logio.so
LoadModule env_module modules/mod_env.so
LoadModule ext_filter_module modules/mod_ext_filter.so
LoadModule mime_magic_module modules/mod_mime_magic.so
LoadModule expires_module modules/mod_expires.so
LoadModule deflate_module modules/mod_deflate.so
LoadModule headers_module modules/mod_headers.so
LoadModule usertrack_module modules/mod_usertrack.so
LoadModule setenvif_module modules/mod_setenvif.so
LoadModule mime_module modules/mod_mime.so
LoadModule dav_module modules/mod_dav.so
LoadModule status_module modules/mod_status.so
LoadModule autoindex_module modules/mod_autoindex.so
LoadModule info_module modules/mod_info.so
LoadModule dav_fs_module modules/mod_dav_fs.so
LoadModule vhost_alias_module modules/mod_vhost_alias.so
LoadModule negotiation_module modules/mod_negotiation.so
LoadModule dir_module modules/mod_dir.so
LoadModule actions_module modules/mod_actions.so
LoadModule speling_module modules/mod_speling.so
LoadModule userdir_module modules/mod_userdir.so
LoadModule alias_module modules/mod_alias.so
LoadModule rewrite_module modules/mod_rewrite.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_balancer_module modules/mod_proxy_balancer.so
LoadModule proxy_ftp_module modules/mod_proxy_ftp.so
LoadModule proxy_http_module modules/mod_proxy_http.so
LoadModule proxy_connect_module modules/mod_proxy_connect.so
LoadModule cache_module modules/mod_cache.so
LoadModule suexec_module modules/mod_suexec.so
LoadModule disk_cache_module modules/mod_disk_cache.so
# LoadModule file_cache_module modules/mod_file_cache.so
# LoadModule mem_cache_module modules/mod_mem_cache.so
LoadModule cgi_module modules/mod_cgi.so
LoadModule version_module modules/mod_version.so

Include conf.d/*.conf

User apache
Group apache
ServerAdmin root@localhost
UseCanonicalName Off
DocumentRoot "/var/www/html"
<Directory />
    Options FollowSymLinks
    AllowOverride None
</Directory>

<Directory "/var/www/html">
    Options Indexes FollowSymLinks
    AllowOverride None
    Order allow,deny
    Allow from all
</Directory>

<IfModule mod_userdir.c>
    #
    # UserDir is disabled by default since it can confirm the presence
    # of a username on the system (depending on home directory
    # permissions).
    #
    UserDir disable

    #
    # To enable requests to /~user/ to serve the user's public_html
    # directory, remove the "UserDir disable" line above, and uncomment
    # the following line instead:
    # 
    #UserDir public_html

</IfModule>

DirectoryIndex index.html index.html.var
AccessFileName .htaccess

<Files ~ "^\.ht">
    Order allow,deny
    Deny from all
</Files>

TypesConfig /etc/mime.types
DefaultType text/plain

<IfModule mod_mime_magic.c>

    MIMEMagicFile conf/magic
</IfModule>

HostnameLookups Off
ErrorLog logs/error_log
LogLevel warn
ServerSignature On

Alias /icons/ "/var/www/icons/"

<Directory "/var/www/icons">
    Options Indexes MultiViews
    AllowOverride None
    Order allow,deny
    Allow from all
</Directory>

<IfModule mod_dav_fs.c>
    # Location of the WebDAV lock database.
    DAVLockDB /var/lib/dav/lockdb
</IfModule>

ScriptAlias /cgi-bin/ "/var/www/cgi-bin/"
<Directory "/var/www/cgi-bin">
    AllowOverride None
    Options None
    Order allow,deny
    Allow from all
</Directory>
IndexOptions FancyIndexing VersionSort NameWidth=* HTMLTable
AddIconByEncoding (CMP,/icons/compressed.gif) x-compress x-gzip

AddIconByType (TXT,/icons/text.gif) text/*
AddIconByType (IMG,/icons/image2.gif) image/*
AddIconByType (SND,/icons/sound2.gif) audio/*
AddIconByType (VID,/icons/movie.gif) video/*

AddIcon /icons/binary.gif .bin .exe
AddIcon /icons/binhex.gif .hqx
AddIcon /icons/tar.gif .tar
AddIcon /icons/world2.gif .wrl .wrl.gz .vrml .vrm .iv
AddIcon /icons/compressed.gif .Z .z .tgz .gz .zip
AddIcon /icons/a.gif .ps .ai .eps
AddIcon /icons/layout.gif .html .shtml .htm .pdf
AddIcon /icons/text.gif .txt
AddIcon /icons/c.gif .c
AddIcon /icons/p.gif .pl .py
AddIcon /icons/f.gif .for
AddIcon /icons/dvi.gif .dvi
AddIcon /icons/uuencoded.gif .uu
AddIcon /icons/script.gif .conf .sh .shar .csh .ksh .tcl
AddIcon /icons/tex.gif .tex
AddIcon /icons/bomb.gif core

AddIcon /icons/back.gif ..
AddIcon /icons/hand.right.gif README
AddIcon /icons/folder.gif ^^DIRECTORY^^
AddIcon /icons/blank.gif ^^BLANKICON^^
DefaultIcon /icons/unknown.gif
ReadmeName README.html
HeaderName HEADER.html
IndexIgnore .??* *~ *# HEADER* README* RCS CVS *,v *,t
AddLanguage ca .ca
AddLanguage cs .cz .cs
AddLanguage da .dk
AddLanguage de .de
AddLanguage el .el
AddLanguage en .en
AddLanguage eo .eo
AddLanguage es .es
AddLanguage et .et
AddLanguage fr .fr
AddLanguage he .he
AddLanguage hr .hr
AddLanguage it .it
AddLanguage ja .ja
AddLanguage ko .ko
AddLanguage ltz .ltz
AddLanguage nl .nl
AddLanguage nn .nn
AddLanguage no .no
AddLanguage pl .po
AddLanguage pt .pt
AddLanguage pt-BR .pt-br
AddLanguage ru .ru
AddLanguage sv .sv
AddLanguage zh-CN .zh-cn
AddLanguage zh-TW .zh-tw

LanguagePriority en ca cs da de el eo es et fr he hr it ja ko ltz nl nn no pl pt pt-BR ru sv zh-CN zh-TW
ForceLanguagePriority Prefer Fallback
AddDefaultCharset UTF-8
AddType application/x-compress .Z
AddType application/x-gzip .gz .tgz
AddHandler type-map var
AddType text/html .shtml
AddOutputFilter INCLUDES .shtml

Alias /error/ "/var/www/error/"

<IfModule mod_negotiation.c>
<IfModule mod_include.c>
    <Directory "/var/www/error">
        AllowOverride None
        Options IncludesNoExec
        AddOutputFilter Includes html
        AddHandler type-map var
        Order allow,deny
        Allow from all
        LanguagePriority en es de fr
        ForceLanguagePriority Prefer Fallback
    </Directory>

</IfModule>
</IfModule>

BrowserMatch "Mozilla/2" nokeepalive
BrowserMatch "MSIE 4\.0b2;" nokeepalive downgrade-1.0 force-response-1.0
BrowserMatch "RealPlayer 4\.0" force-response-1.0
BrowserMatch "Java/1\.0" force-response-1.0
BrowserMatch "JDK/1\.0" force-response-1.0
BrowserMatch "Microsoft Data Access Internet Publishing Provider" redirect-carefully
BrowserMatch "MS FrontPage" redirect-carefully
BrowserMatch "^WebDrive" redirect-carefully
BrowserMatch "^WebDAVFS/1.[0123]" redirect-carefully
BrowserMatch "^gnome-vfs/1.0" redirect-carefully
BrowserMatch "^XML Spy" redirect-carefully
BrowserMatch "^Dreamweaver-WebDAV-SCM1" redirect-carefully

# Include vhost configurations
Include /etc/httpd/vhosts.d/*.conf
]] )
    -- write footer
    LC.liveconfig.writeFooter(fh)
    fh:close()

    -- create new ssl.conf file:
    fh, msg = io.open(configpath .. "/conf.d/ssl.conf", "w")
    if fh == nil then
      LC.log.print(LC.log.ERR, "Can't open '", configpath, "/conf.d/ssl.conf' for writing: ", msg)
      return false, "Can't open '" .. configpath .. "/conf.d/ssl.conf' for writing: " .. msg
    end

    -- write header
    LC.liveconfig.writeHeader(fh)

    fh:write( [[

LoadModule ssl_module modules/mod_ssl.so
SSLPassPhraseDialog  builtin
SSLSessionCache         shmcb:/var/cache/mod_ssl/scache(512000)
SSLSessionCacheTimeout  300
SSLMutex default
SSLRandomSeed startup file:/dev/urandom  256
SSLRandomSeed connect builtin
SSLCryptoDevice builtin

]] )
    -- write footer
    LC.liveconfig.writeFooter(fh)
    fh:close()

  end -- if LC.distribution.family == "RedHat"

  -- create directory for vhosts:
  if not LC.fs.is_dir(vhostpath) then
    LC.fs.mkdir(vhostpath)
    LC.fs.setperm(vhostpath, 750, "root", cfg.httpd_group)
  end

  -- create 'liveconfig.conf' config file
  fh, msg = io.open(configfile, "w")
  if fh == nil then
    LC.log.print(LC.log.ERR, "Can't open '", configfile, "' for writing: ", msg)
    return false, "Can't open '" .. configfile .. "' for writing: " .. msg
  end

  -- write header
  LC.liveconfig.writeHeader(fh)

  -- write config...
  fh:write([[

# Access logging
# We define a special log format here, which gets piped into the 'lclogsplit'
# utility (see lclogsplit(1) for more details).
# This way Apache httpd needs only one file handle for all access_log files,
# and we get nice real-time statistics on HTTP traffic.
# IMPORTANT: the module 'mod_logio' needs to be enabled!

<IfModule mod_logio.c>
  LogFormat "%v:#:%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\" %I %O" LiveConfig
</IfModule>

<IfModule !mod_logio.c>
  LogFormat "%v:#:%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"" LiveConfig
</IfModule>

]])
  fh:write("CustomLog \"||", LC.liveconfig.libexecdir, "/lclogsplit -m ", configpath, "/accesslog.map -s ", LC.liveconfig.localstatedir, "/lib/liveconfig/apachelog.stats\" LiveConfig\n\n")
  fh:write("\n")

  if LC.distribution.family == "Debian" then
    -- for Debian, add global "ErrorLog"
    fh:write("ErrorLog /var/log/apache2/error.log\n\n")
  end
  -- RedHat/CentOS has its ErrorLog directove in /etc/httpd/httpd.conf
  -- Gentoo has its ErrorLog directive in /etc/apache2/modules.d/00_default_settings.conf

  -- write footer
  LC.liveconfig.writeFooter(fh)

  fh:close()

  if LC.fs.is_dir("/etc/apache2/conf-enabled") and LC.fs.is_file("/usr/sbin/a2enconf") then
    -- enable configuration
    os.execute("/usr/sbin/a2enconf liveconfig")
  end

  if LC.distribution.family == "Debian" then
    if LC.fs.is_file(configpath .. "/ports.conf") then
      -- Debian has a "ports.conf" file, containing the "Listen" directives
      -- for Apache. Remove this, and add a note that Listen commands are now
      -- in the default vhost config file
      if not LC.fs.is_file(configpath .. "/ports.conf.lcbak") then
        -- only back up if not done yet
        LC.fs.rename(configpath .. "/ports.conf", configpath .. "/ports.conf.lcbak")
      end
      fh, msg = io.open(configpath .. "/ports.conf", "w")
      if fh == nil then
        LC.log.print(LC.log.ERR, "Can't open '", configpath .. "/ports.conf", "' for writing: ", msg)
        return false, "Can't open '" .. configpath .. "/ports.conf", "' for writing: " .. msg
      end
      LC.liveconfig.writeHeader(fh)
      fh:write([[

# The "Listen" and "NameVirtualHost" directives are now in the first
# vhost configuration file (usually /etc/apache2/sites-available/default)
#
# The original "ports.conf" file has been backed up at "ports.conf.lcbak"

]])
      LC.liveconfig.writeFooter(fh)
      fh:close()
    end
    if LC.fs.is_file(vhostpath .. "/000-default.conf") then
      vhostfile = "000-default.conf"
    else
      vhostfile = "default"
    end
  elseif LC.distribution.family == "Gentoo" then
    vhostfile = "00_default_vhost.conf"
    -- remove default ssl vhost file (if existing)
    if LC.fs.is_file(vhostpath .. "/00_default_ssl_vhost.conf") then
      LC.fs.rename(vhostpath .. "/00_default_ssl_vhost.conf", vhostpath .. "/00_default_ssl_vhost.conf.lcbak")
    end
  elseif LC.distribution.family == "RedHat" then
    vhostfile = "00_default_vhost.conf"
  elseif LC.distribution.family == "SUSE" then
    if LC.fs.is_file(configpath .. "/listen.conf") then
      -- SUSE has a "listen.conf" file, containing the "Listen" directives
      -- for Apache. Remove this, and add a note that Listen commands are now
      -- in the default vhost config file
      if not LC.fs.is_file(configpath .. "/listen.conf.lcbak") then
        -- only back up if not done yet
        LC.fs.rename(configpath .. "/listen.conf", configpath .. "/listen.conf.lcbak")
      end
      fh, msg = io.open(configpath .. "/listen.conf", "w")
      if fh == nil then
        LC.log.print(LC.log.ERR, "Can't open '", configpath .. "/listen.conf", "' for writing: ", msg)
        return false, "Can't open '" .. configpath .. "/listen.conf", "' for writing: " .. msg
      end
      LC.liveconfig.writeHeader(fh)
      fh:write([[

# The "Listen" and "NameVirtualHost" directives are now in the first
# vhost configuration file (usually /etc/apache2/vhosts.d/default.conf)
#
# The original "listen.conf" file has been backed up at "listen.conf.lcbak"

]])
      LC.liveconfig.writeFooter(fh)
      fh:close()
    end
    vhostfile = "default.conf"
  else
    LC.log.print(LC.log.ERR, "Distribution family '", LC.distribution.family, "' not supported (yet)")
    return false, "Distribution family '" .. LC.distribution.family .. "' not supported (yet)"
  end

  -- create log map file
  if not LC.fs.is_file(configpath .. "/accesslog.map") then
    fh, msg = io.open(configpath .. "/accesslog.map", "w")
    if fh == nil then
      LC.log.print(LC.log.ERR, "Can't open '", configpath .. "/accesslog.map", "' for writing: ", msg)
      return false, "Can't open '" .. configpath .. "/accesslog.map" .. "' for writing: " .. msg
    end
    -- write header
    LC.liveconfig.writeHeader(fh)
    if LC.distribution.family == "RedHat" then
      fh:write("default /var/log/httpd/access_log\n")
    else
      fh:write("default /var/log/apache2/access.log\n")
    end
    LC.liveconfig.writeFooter(fh)
    fh:close()
  end

  -- back up old default vhost file (if existing)
  if LC.fs.is_file(vhostpath .. "/" .. vhostfile) and not LC.fs.is_file(vhostpath .. "/" .. vhostfile .. ".lcbak") then
    LC.fs.rename(vhostpath .. "/" .. vhostfile, vhostpath .. "/" .. vhostfile .. ".lcbak")
  end

  -- write default vhost file:
  configure(cfg, opts)

  -- set permissions for lclogsplit under RedHat
  if LC.distribution.family == "RedHat" then
    os.execute("chcon -v --type=httpd_exec_t /usr/lib/liveconfig/lclogsplit")
  end
  -- write status file
  LC.liveconfig.writeStatus(statusfile, cfg.type, 0, os.date("%Y-%m-%d %H:%M:%S %Z"))

  return true
end

-- ---------------------------------------------------------------------------
-- uninstall(cfg, opts)
--
-- Remove LiveConfig configuration files from Apache httpd
-- ---------------------------------------------------------------------------
function uninstall(cfg, opts)
  LC.log.print(LC.log.INFO, "Disabling management of Apache httpd")

  local status, msg
  local configpath = cfg["configpath"]
  local configfile = cfg["configfile"]
  local statusfile = cfg["statusfile"]
  local vhostpath  = cfg["available_dir"] or cfg["enabled_dir"]

  if opts and opts.prefix then
    -- use prefix (for testing etc.)
    configpath = opts.prefix .. configpath
    configfile = opts.prefix .. configfile
    statusfile = opts.prefix .. statusfile
    vhostpath = opts.prefix .. vhostpath
  end

  -- remove config file
  status, msg = os.remove(configfile)
  if status == nil then
    LC.log.print(LC.log.ERR, "Deletion of '", configfile, "' failed: ", msg)
  end

  if LC.distribution.family == "Debian" then
    if LC.fs.is_file(vhostpath .. "/000-default.conf") then
      vhostfile = "000-default.conf"
    else
      vhostfile = "default"
    end
    -- restore original "ports.conf" (if existing...)
    if LC.fs.is_file(configpath .. "/ports.conf") and LC.fs.is_file(configpath .. "/ports.conf.lcbak") then
      LC.fs.rename(configpath .. "/ports.conf.lcbak", configpath .. "/ports.conf")
    end
  elseif LC.distribution.family == "RedHat" then
    vhostfile = "00_default_vhost.conf"
    -- restore original "httpd.conf" (if existing...)
    if LC.fs.is_file(configpath .. "/httpd.conf") and LC.fs.is_file(configpath .. "/httpd.conf.lcbak") then
      LC.fs.rename(configpath .. "/httpd.conf.lcbak", configpath .. "/httpd.conf")
    end
    -- restore original "ssl.conf" (if existing...)
    if LC.fs.is_file(configpath .. "/conf.d/ssl.conf.lcbak") then
      LC.fs.rename(configpath .. "/conf.d/ssl.conf.lcbak", configpath .. "/conf.d/ssl.conf")
    end
  elseif LC.distribution.family == "SUSE" then
    vhostfile = "default.conf"
    -- restore original "listen.conf" (if existing...)
    if LC.fs.is_file(configpath .. "/listen.conf") and LC.fs.is_file(configpath .. "/listen.conf.lcbak") then
      LC.fs.rename(configpath .. "/listen.conf.lcbak", configpath .. "/listen.conf")
    end
    -- remove our "default.conf" file
    if LC.fs.is_file(vhostpath .. "/" .. vhostfile) then
      os.remove(vhostpath .. "/" .. vhostfile)
    end
  elseif LC.distribution.family == "Gentoo" then
    vhostfile = "00_default_vhost.conf"
  else
    LC.log.print(LC.log.ERR, "Distribution family '", LC.distribution.family, "' not supported (yet)")
    return false, "Distribution family '" .. LC.distribution.family .. "' not supported (yet)"
  end

  -- restore old default vhost file (if existing)
  if LC.fs.is_file(vhostpath .. "/" .. vhostfile .. ".lcbak") then
    LC.fs.rename(vhostpath .. "/" .. vhostfile .. ".lcbak", vhostpath .. "/" .. vhostfile)
  end

  -- restore default ssl vhost file
  if LC.distribution.family == "Gentoo" then
      if LC.fs.is_file(vhostpath .. "/00_default_ssl_vhost.conf.lcbak") then
        LC.fs.rename(vhostpath .. "/00_default_ssl_vhost.conf.lcbak", vhostpath .. "/00_default_ssl_vhost.conf")
      end
  end

  -- remove accesslog map file
  if LC.fs.is_file(configpath .. "/accesslog.map") then
    os.remove(configpath .. "/accesslog.map")
  end

  -- remove status file
  if LC.fs.is_file(statusfile) then
      os.remove(statusfile)
  end

  return true
end


-- ---------------------------------------------------------------------------
-- configure(cfg, opts)
--
-- Configure Apache httpd
-- ---------------------------------------------------------------------------
function configure(cfg, opts)

  local fh, status, msg
  local configpath = cfg["configpath"]
  local statusfile = cfg["statusfile"]
  local vhostpath  = cfg["available_dir"] or cfg["enabled_dir"]
  local vhostfile  -- set below (distribution-specific)

  if opts and opts.prefix then
    -- use prefix (for testing etc.)
    configpath = opts.prefix .. configpath
    statusfile = opts.prefix .. statusfile
    vhostpath  = opts.prefix .. vhostpath
  end

  if LC.distribution.family == "Debian" then
    if LC.fs.is_file(vhostpath .. "/000-default.conf") then
      vhostfile = "000-default.conf"
    else
      vhostfile = "default"
    end
  elseif LC.distribution.family == "Gentoo" or LC.distribution.family == "RedHat" then
    vhostfile = "00_default_vhost.conf"
  elseif LC.distribution.family == "SUSE" then
    vhostfile = "default.conf"
  else
    LC.log.print(LC.log.ERR, "Distribution family '", LC.distribution.family, "' not supported (yet)")
    return false, "Distribution family '" .. LC.distribution.family .. "' not supported (yet)"
  end

  fh, msg = io.open(vhostpath .. "/" .. vhostfile, "w")
  if fh == nil then
    LC.log.print(LC.log.ERR, "Can't open '", vhostpath .. "/" .. vhostfile, "' for writing: ", msg)
    return false, "Can't open '" .. vhostpath .. "/" .. vhostfile.. "' for writing: " .. msg
  end
  LC.liveconfig.writeHeader(fh)

  fh:write([[
# Default VirtualHost configuration
# Automatically created by LiveConfig

]])

  local interfaces = "", i

  -- SSL configuration
  if opts.ssl_interfaces ~= nil then
    fh:write("<IfModule mod_ssl.c>\n")
    fh:write("  SSLProtocol ALL -SSLv2\n")
    fh:write("  SSLHonorCipherOrder on\n")
    if opts.ssl_pci then
      fh:write("  SSLCipherSuite ", LC.liveconfig.DEFAULT_SSL_PCI_CIPHERS, "\n")
    else
      fh:write("  SSLCipherSuite ", LC.liveconfig.DEFAULT_SSL_CIPHERS, "\n")
    end
    for i=1, #opts.ssl_interfaces do
      fh:write("  Listen ", opts.ssl_interfaces[i], "\n")
      fh:write("  NameVirtualHost ", opts.ssl_interfaces[i], "\n")
    end
    fh:write("</IfModule>\n\n")
  end -- HTTPS interfaces

  if opts.interfaces == nil then
    fh:write("# NO HTTP INTERFACES CONFIGURED!\n")
  else
    for i=1, #opts.interfaces do
      interfaces = interfaces .. " " .. opts.interfaces[i]
      fh:write("Listen ", opts.interfaces[i], "\n")
      fh:write("NameVirtualHost ", opts.interfaces[i], "\n")
    end
  end

  if opts.interfaces ~= nil or opts.ssl_interfaces ~= nil then
    fh:write([[

ServerName default

Alias /.errorFiles/ ]], LC.liveconfig.datadir, [[/html/
<Directory "]], LC.liveconfig.datadir, [[/html/">
    Options SymLinksIfOwnerMatch IncludesNOEXEC
    AllowOverride None
    Order allow,deny
    allow from all
    <IfModule mod_rewrite.c>
        RewriteEngine On
        RewriteRule ^$  /_404_
    </IfModule>
    <IfModule mod_include.c>
        AddType text/html .shtml
        AddOutputFilter INCLUDES .shtml
        ErrorDocument 404 /not-available.shtml
        <IfModule !mod_rewrite.c>
            DirectoryIndex not-available.shtml
        </IfModule>
    </IfModule>
    <IfModule !mod_include.c>
        ErrorDocument 404 /not-available.html
        <IfModule !mod_rewrite.c>
            DirectoryIndex not-available.html
        </IfModule>
    </IfModule>
</Directory>

]])

  end

  if opts.interfaces ~= nil then
    -- default HTTP host
    fh:write([[

<VirtualHost]], interfaces, [[>

    Servername default
    DocumentRoot "]], LC.liveconfig.datadir, [[/html/"

]])

    if LC.fs.is_file(vhostpath .. "/default.inc") then
      fh:write("    Include ", vhostpath, "/default.inc\n")
    end

    fh:write("</VirtualHost>\n\n")

  end

  LC.liveconfig.writeFooter(fh)
  fh:close()

  -- update status file
  LC.liveconfig.writeStatus(statusfile, cfg.type, opts.revision, os.date("%Y-%m-%d %H:%M:%S %Z"))

  -- restart web server (not just reload, so changed interface configuration can be applied)
  LC.timeout.set('apache.restart', 10, 60)

  return true
end

-- ---------------------------------------------------------------------------
-- updateMapFile(cfg, opts, domains, logname)
--
-- Update, add or delete an entry in accesslog.map file (for lclogsplit)
-- ---------------------------------------------------------------------------
local function updateMapFile(cfg, opts, domains, logname)
  local configpath = cfg["configpath"]
  local i
  local domainlist = { }

  -- copy every entry from "domains" table as key into "domainlist" table
  -- (for faster access to this table when checking matched domains)
  for i=1, #domains do
    domainlist[domains[i]] = true
  end

  if opts and opts.prefix then
    -- use prefix (for testing etc.)
    configpath = opts.prefix .. configpath
  end

  local search = " " .. logname

  local fhr, fhw, msg
  fhr, msg = io.open(configpath .. "/accesslog.map", "r")
  if fhr == nil then
    LC.log.print(LC.log.ERR, "Can't open '", configpath .. "/accesslog.map", "' for reading: ", msg)
    return false, "Can't open '" .. configpath .. "/accesslog.map" .. "' for reading: " .. msg
  end

  fhw, msg = io.open(configpath .. "/accesslog.map.tmp", "w")
  if fhw == nil then
    LC.log.print(LC.log.ERR, "Can't open '", configpath .. "/accesslog.map.tmp", "' for writing: ", msg)
    fhr:close()
    return false, "Can't open '" .. configpath .. "/accesslog.map.tmp" .. "' for writing: " .. msg
  end

  local line
  while true do
    line = fhr:read()
    if line == nil then break end
    if string.find(line, search) then
      -- remove this entry from map file
      line = nil
    end
    if line ~= nil then
      fhw:write(line, "\n")
    end
  end

  for i in pairs(domainlist) do
    -- entry not found, so add new one:
    local f4 = opts.filterv4
    if f4 == nil then f4 = 0 end
    local f6 = opts.filterv6
    if f6 == nil then f6 = 0 end
    fhw:write(i, " ", logname, " ", f4, "/", f6, "\n")
  end

  fhw:close()
  fhr:close()

  -- rename map file
  LC.fs.rename(configpath .. "/accesslog.map.tmp", configpath .. "/accesslog.map")

end

-- ---------------------------------------------------------------------------
local function writeVHostIPs(fh, vhost)
  local i, key
  fh:write("<VirtualHost")
  for i, key in ipairs(vhost.ips) do
    if vhost.ssl then
      if string.find(key, ":") then
        -- IPv6 address
        fh:write(" [", key, "]:443")
      else
        -- IPv4 address
        fh:write(" ", key, ":443")
      end
    else
      if string.find(key, ":") then
        -- IPv6 address
        fh:write(" [", key, "]:80")
      else
        -- IPv4 address
        fh:write(" ", key, ":80")
      end
    end
  end
  fh:write(">\n")
end

-- ---------------------------------------------------------------------------
local function writeVHostSSL(fh, cfg, vhost)
  -- SSL configuration:
  fh:write("    SSLEngine On\n")
  if vhost.ssl_pci then
    -- PCI-compliant cipher suite
    fh:write("    SSLCipherSuite ", LC.liveconfig.DEFAULT_SSL_PCI_CIPHERS, "\n")
  else
    fh:write("    SSLCipherSuite ", LC.liveconfig.DEFAULT_SSL_CIPHERS, "\n")
  end
  -- create/update SSL certificate file:
  local sfh
  local fname = cfg.ssl_cert_dir .. "/" .. vhost.ssl_filename .. ".crt"
  sfh, msg = io.open(fname, "w")
  if sfh == nil then
    LC.log.print(LC.log.ERR, "Can't open '", fname, "' for writing: ", msg)
    return false, "Can't open '" .. fname .. "' for writing: " .. msg
  end
  sfh:write(vhost.ssl_crt)
  sfh:close()
  LC.fs.setperm(fname, "0644", "root", "root")
  fh:write("    SSLCertificateFile ", fname, "\n")

  -- create/update SSL key file:
  fname = cfg.ssl_key_dir .. "/" .. vhost.ssl_filename .. ".key"
  sfh, msg = io.open(fname, "w")
  if sfh == nil then
    LC.log.print(LC.log.ERR, "Can't open '", fname, "' for writing: ", msg)
    return false, "Can't open '" .. fname .. "' for writing: " .. msg
  end
  sfh:write(vhost.ssl_key)
  sfh:close()
  LC.fs.setperm(fname, cfg["ssl_key_mode"], cfg["ssl_key_user"], cfg["ssl_key_group"])
  fh:write("    SSLCertificateKeyFile ", fname, "\n")

  -- create/update SSL CA chain file:
  if vhost.ssl_ca ~= nil then
    fname = cfg.ssl_cert_dir .. "/" .. vhost.ssl_filename .. "-ca.crt"
    sfh, msg = io.open(fname, "w")
    if sfh == nil then
      LC.log.print(LC.log.ERR, "Can't open '", fname, "' for writing: ", msg)
      return false, "Can't open '" .. fname .. "' for writing: " .. msg
    end
    sfh:write(vhost.ssl_ca)
    sfh:close()
    LC.fs.setperm(fname, "0644", "root", "root")
    fh:write("    SSLCertificateChainFile ", fname, "\n")
  end

  fh:write("\n")
end

-- ---------------------------------------------------------------------------
local function php2int(str)
  if str == nil then return end
  local val, unit = string.match(str, "(%d+)([KMG]?)")
  val = tonumber(val)
  if unit == "K" then
    val = val * 1024
  elseif unit == "M" then
    val = val * 1048576
  elseif unit == "G" then
    val = val * 1073741824
  end
  return val
end

-- ---------------------------------------------------------------------------
local function writeVHostDocRoot(fh, cfg, opts, vhost, path)

  if opts.path then
    -- we have a DocumentRoot
    fh:write("    DocumentRoot \"", path, "\"\n")
    fh:write("    <Directory \"", path, "\">\n")
    fh:write("        Options SymLinksIfOwnerMatch MultiViews")
    if opts.hasCGI and opts.hasSSI then
      fh:write(" Includes")
    elseif opts.hasSSI then
      fh:write(" IncludesNOEXEC")
    end
    fh:write("\n")
    fh:write("        AllowOverride AuthConfig FileInfo Indexes Limit Options=Indexes,MultiViews,FollowSymLinks,SymLinksIfOwnerMatch")
    if opts.hasCGI then
      fh:write(",ExecCGI")
    end
    fh:write("\n")
    fh:write("        Order allow,deny\n")
    fh:write("        allow from all\n")
    fh:write("    </Directory>\n\n")
  end

  -- error.log enabled?
  if opts.errorlog then
    fh:write("    ErrorLog \"", opts.path, "/logs/error.log\"\n\n")
    if not LC.fs.is_file(opts.path .. "/logs/error.log") then
      -- touch file
      local fh, msg = io.open(opts.path .. "/logs/error.log", "w")
      fh:close()
    end
    -- make error.log readable. the 'logs' directory itself is protected against unauthorized access
    LC.fs.setperm(opts.path .. "/logs/error.log", 644, "root", "root")
  end

  -- CGI allowed?
  if opts.hasCGI then
    -- check if cgi-bin exists, eventually create it:
    if not LC.fs.is_dir(opts.path .. "/" .. LC.web.HTDOCS_PATH .. "/cgi-bin") then
      LC.fs.mkdir(opts.path .. "/" .. LC.web.HTDOCS_PATH .. "/cgi-bin")
      LC.fs.setperm(opts.path .. "/" .. LC.web.HTDOCS_PATH .. "/cgi-bin", 755, opts.user, opts.group)
      if LC.distribution.family == "RedHat" then
        os.execute("chcon --type=user_home_t \"" .. opts.path .. "/cgi-bin\"")
      end
    end
    fh:write("    ScriptAlias /cgi-bin/ \"", opts.path, "/" .. LC.web.HTDOCS_PATH .. "/cgi-bin/\"\n\n")

    -- configure suExec User/Group
    if opts.user ~= nil and opts.group ~= nil then
      fh:write("    <IfModule mod_suexec.c>\n")
      fh:write("        SuexecUserGroup ", opts.user, " ", opts.group, "\n")
      fh:write("    </IfModule>\n\n")
    end
  else
    -- forbid access to /cgi-bin/ directory!
    fh:write("    <Directory \"", opts.path, "/" .. LC.web.HTDOCS_PATH .. "/cgi-bin\">\n")
    fh:write("        Order allow,deny\n")
    fh:write("        deny from all\n")
    fh:write("    </Directory>\n\n")
  end

  -- configure for mpm_itk?
  if LC.liveconfig.inTable("mpm_itk", cfg.modules) then
    fh:write("    <IfModule mpm_itk_module>\n")
    fh:write("        AssignUserID ", opts.user, " ", opts.group, "\n")
    fh:write("    </IfModule>\n\n")
  end

  -- configure tmp directory
  if opts.hasCGI or opts.hasPHP or opts.hasSSI then
    fh:write("    <IfModule mod_env.c>\n")
    fh:write("        SetEnv TMP \"", opts.path, "/tmp\"\n")
    fh:write("        SetEnv TMPDIR \"", opts.path, "/tmp\"\n")
    fh:write("    </IfModule>\n\n")
  end

  -- PHP settings
  if opts.hasPHP and opts.hasPHP > 0 then
    -- PHP enabled:
    local phpmode = { "suPHP", "FastCGI", "mod_php" }
    fh:write("    # PHP configuration for this subscription: ")
    if opts.hasPHP == 1 then
      local handler = "application/x-httpd-suphp"
      if LC.distribution.family == "RedHat" then
        handler = "x-httpd-php"
      elseif LC.distribution.family == "SUSE" then
        handler = "application/x-httpd-php"
      end
      fh:write("suPHP\n")
      -- suPHP configuration
      fh:write("    <IfModule mod_suphp.c>\n")
      fh:write("        <IfModule mod_php5.c>\n")
      fh:write("            php_admin_flag engine off\n")
      fh:write("            <FilesMatch \"\\.ph(p3?|tml)$\">\n")
      fh:write("                SetHandler ", handler, "\n")
      fh:write("            </FilesMatch>\n")
        -- FilesMatch for Debian 7:
        fh:write("            <FilesMatch \".+\\.ph(p[345]?|t|tml)$\">\n")
        fh:write("                SetHandler ", handler, "\n")
        fh:write("            </FilesMatch>\n")
      if LC.distribution.family == "SUSE"  then
        fh:write("            <FilesMatch \"\\.ph(p[345]?|tml)$\">\n")
        fh:write("                SetHandler ", handler, "\n")
        fh:write("            </FilesMatch>\n")
      end
      fh:write("        </IfModule>\n")
      fh:write("        suPHP_Engine on\n")
      if LC.distribution.family == "RedHat"  then
        fh:write("        suPHP_AddHandler x-httpd-php\n")
      end
      -- add suPHP_User and suPHP_Group for RHEL/CentOS:
      if LC.distribution.family == "RedHat" or LC.distribution.family == "SUSE" then
        if opts.user ~= nil and opts.group ~= nil then
          fh:write("        suPHP_UserGroup ", opts.user, " ", opts.group, "\n")
        end
      end
      if LC.fs.is_file(opts.path .. "/.php5/php.ini") then
        -- use custom php.ini file
        fh:write("        suPHP_ConfigPath ", opts.path, "/.php5/\n")
      elseif LC.fs.is_file(opts.path .. "/conf/php5/php.ini") then
        -- use php.ini file customized by LiveConfig
        fh:write("        suPHP_ConfigPath ", opts.path, "/conf/php5/\n")
      end
      fh:write("    </IfModule>\n\n")

    elseif opts.hasPHP == 2 then
      fh:write("FastCGI\n")
      -- FastCGI configuration
      fh:write("    <IfModule mod_fcgid.c>\n")
      fh:write("        <IfModule mod_php5.c>\n")
      fh:write("            php_admin_flag engine off\n")
      fh:write("            <FilesMatch \"\\.ph(p3?|tml)$\">\n")
      fh:write("                SetHandler None\n")
      fh:write("            </FilesMatch>\n")
        -- FilesMatch for Debian 7:
        fh:write("            <FilesMatch \".+\\.ph(p[345]?|t|tml)$\">\n")
        fh:write("                SetHandler None\n")
        fh:write("            </FilesMatch>\n")
      fh:write("        </IfModule>\n")
      if LC.distribution.family == "SUSE"  then
        fh:write("            <FilesMatch \"\\.ph(p[345]?|tml)$\">\n")
        fh:write("                SetHandler None\n")
        fh:write("            </FilesMatch>\n")
      end
      if not opts.hasCGI then
        -- if not already defined, set suexecUserGroup here:
        fh:write("        <IfModule mod_suexec.c>\n")
        fh:write("            SuexecUserGroup ", opts.user, " ", opts.group, "\n")
        fh:write("        </IfModule>\n\n")
      end
      fh:write("        <FilesMatch \"\\.php5?$\">\n")
      fh:write("            Options +ExecCGI\n")
      fh:write("            SetHandler fcgid-script\n")
      fh:write("        </FilesMatch>\n")
      fh:write("        FcgidWrapper ", opts.path, "/conf/php5/php-fcgi-starter .php\n")
      fh:write("        FcgidWrapper ", opts.path, "/conf/php5/php-fcgi-starter .php5\n")
      if opts.phpini and opts.phpini['post_max_size'] then
        local val = php2int(opts.phpini['post_max_size'].value)
        fh:write("        FcgidMaxRequestLen ", val, "\n")
      end
      if opts.phpini and (opts.phpini['max_execution_time'] or opts.phpini['max_input_time']) then
        local timeout = 40
        if opts.phpini['max_execution_time'] then
          local val = php2int(opts.phpini['max_execution_time'].value)
          if timeout < val then timeout = val end
        end
        if opts.phpini['max_input_time'] then
          local val = php2int(opts.phpini['max_input_time'].value)
          if timeout < val then timeout = val end
        end
        fh:write("        FcgidIOTimeout ", timeout, "\n")
      end

      fh:write("        FcgidMaxRequestsPerProcess 5000\n")
      fh:write("    </IfModule>\n")
      -- create/update FastCGI wrapper scripts
      local phpidx
      for phpidx in pairs(LCS.web.phpVersions) do
        local php = LCS.web.phpVersions[phpidx]
        local inputfile = php.ini
        local code = php.code
        local pfh, msg = io.open(opts.path .. "/conf/" .. code .. "/php-fcgi-starter.tmp", "w")
        if pfh == nil then
          LC.log.print(LC.log.ERR, "Can't open '", opts.path .. "/conf/" .. code .. "/php-fcgi-starter.tmp", "' for writing: ", msg)
        else
          LC.fs.setperm(opts.path .. "/conf/" .. code .. "/php-fcgi-starter.tmp", 550, opts.user, opts.group)
          pfh:write("#!/bin/sh\n")
          pfh:write("umask 0022\n")
          if LC.fs.is_file(opts.path .. "/.php5/php.ini") then
            -- use custom php.ini file
            pfh:write("PHPRC=", opts.path, "/.php5/\n")
          elseif LC.fs.is_file(opts.path .. "/conf/" .. code .. "/php.ini") then
            -- use php.ini file customized by LiveConfig
            pfh:write("PHPRC=", opts.path, "/conf/" .. code .. "/\n")
          end
          pfh:write("export PHPRC\n")
          -- set PHP_FCGI_MAX_REQUESTS
          pfh:write("PHP_FCGI_MAX_REQUESTS=5000\n")
          pfh:write("export PHP_FCGI_MAX_REQUESTS\n")
          -- export TMP and TMPDIR variable for custom temp directory:
          pfh:write("TMP=", opts.path, "/tmp\n")
          pfh:write("export TMP\n")
          pfh:write("TMPDIR=", opts.path, "/tmp\n")
          pfh:write("export TMPDIR\n")
          pfh:write("exec " .. php.bin .. "\n")
          pfh:close()
          if LC.fs.is_file(opts.path .. "/conf/" .. code .. "/php-fcgi-starter") then
            -- remove "immutable" flag:
            os.execute("chattr -i " .. opts.path .. "/conf/" .. code .. "/php-fcgi-starter")
          end
          LC.fs.rename(opts.path .. "/conf/" .. code .. "/php-fcgi-starter.tmp", opts.path .. "/conf/" .. code .. "/php-fcgi-starter")
          -- set SELinux permissions
          if LC.distribution.family == "RedHat" then
            os.execute("chcon --type=httpd_sys_script_exec_t \"" .. opts.path .. "/conf/" .. code .. "/php-fcgi-starter\"")
          end
          -- set "immutable" flag:
          os.execute("chattr +i " .. opts.path .. "/conf/" .. code .. "/php-fcgi-starter")

        end
      end

    elseif opts.hasPHP == 3 then
      fh:write("mod_php\n")
      -- mod_php configuration
      fh:write("    <IfModule mod_php5.c>\n")
      if LC.distribution.family == "Debian" then
        -- re-add handler for application/x-httpd (eg. if suPHP is also available)
        fh:write("        <FilesMatch \".+\\.ph(p[345]?|t|tml)$\">\n")
        fh:write("            SetHandler application/x-httpd-php\n")
        fh:write("        </FilesMatch>\n")
      elseif LC.distribution.family == "Redhat" then
        fh:write("        AddHandler php5-script .php\n")
      end
      local pv = LCS.web.phpVersionInt    -- PHP version (as integer, eg. "50411")
      local i, value, v_min, v_max
      for i in pairs(opts.phpini) do
        value = opts.phpini[i].value
        value = string.gsub(value, "%%HOME%%", opts.path)
        v_min = opts.phpini[i].min  -- minimum supported PHP version (as integer)
        v_max = opts.phpini[i].max  -- supported up to this PHP version (not included)
        if pv == nil or ((v_min == nil or pv >= v_min) and (v_max == nil or pv < v_max)) then
          fh:write("        php_")
          if opts.phpini[i].o == nil or opts.phpini[i].o == false then
            fh:write("admin_")
          end
          if opts.phpini[i].t and opts.phpini[i].t == 'b' then
            fh:write("flag")
          else
            fh:write("value")
          end
          fh:write(" ", i, " ", value, "\n")
        end
      end
      fh:write("    </IfModule>\n\n")
    else
      fh:write("-unknown- (", opts.hasPHP, ")\n")
    end

  else
    -- PHP disabled:

    -- suPHP configuration
    fh:write("    <IfModule mod_suphp.c>\n")
    fh:write("        suPHP_Engine Off\n")
    fh:write("    </IfModule>\n\n")

    -- mod_php configuration
    fh:write("    <IfModule mod_php5.c>\n")
    fh:write("        php_admin_flag engine Off\n")
    fh:write("    </IfModule>\n\n")
  end

  if opts.pwprotect ~= nil then
    local pwpath
    fh:write("    # password-protected directories:\n")
    for pwpath in pairs(opts.pwprotect) do
      fh:write("    <Directory \"", opts.path, escape(pwpath), "\">\n")
      fh:write("        AuthType Basic\n")
      fh:write("        AuthUserFile ", opts.path, "/conf/.htpasswd\n")
      fh:write("        AuthGroupFile /dev/null\n")
      fh:write("        AuthName \"", escape(opts.pwprotect[pwpath].title), "\"\n")
      if opts.pwprotect[pwpath].users[1] == "*" then
        fh:write("        Require valid-user\n")
      else
        fh:write("        Require user")
        local i
        for i in pairs(opts.pwprotect[pwpath].users) do
          fh:write(" \"", escape(opts.pwprotect[pwpath].users[i]), "\"")
        end
        fh:write("\n")
      end
      fh:write("    </Directory>\n")
    end
    fh:write("\n")
  end

end

-- ---------------------------------------------------------------------------
local function writeVHostStats(fh, cfg, opts)
  fh:write("        # Web statistics:\n")
  if opts.webstats.software == 1 then
    -- shared resources for Webalizer
    fh:write("        RewriteCond %{HTTP_HOST} ^", string.gsub(opts.webstats.domain, "%.", "\\."), "$ [NC]\n")
    fh:write("        RewriteRule ^/", string.gsub(opts.webstats.path, "%.", "\\."), "/images/(.*) /usr/share/liveconfig/html/webalizer/$1 [L]\n")
  elseif opts.webstats.software == 2 then
    -- shared resources for AWStats
    local icondir = "/usr/share/awstats/icon"
    if LC.distribution.family == "RedHat" then
      icondir = "/var/www/awstats/icon"
    elseif LC.distribution.family == "SUSE" then
      icondir = "/usr/share/awstats/icon"
    elseif LC.distribution.family == "Gentoo" then
      icondir = "/usr/share/awstats/wwwroot/icon"
    end
    fh:write("        RewriteCond %{HTTP_HOST} ^", string.gsub(opts.webstats.domain, "%.", "\\."), "$ [NC]\n")
    fh:write("        RewriteRule ^/", string.gsub(opts.webstats.path, "%.", "\\."), "/icon/(.*) ", icondir, "/$1 [L]\n")
    fh:write("        RewriteCond %{HTTP_HOST} ^", string.gsub(opts.webstats.domain, "%.", "\\."), "$ [NC]\n")
    fh:write("        RewriteRule ^/", string.gsub(opts.webstats.path, "%.", "\\."), "/awstats/(.*) /usr/share/liveconfig/html/awstats/$1 [L]\n")
  end
  fh:write("        RewriteCond %{HTTP_HOST} ^", string.gsub(opts.webstats.domain, "%.", "\\."), "$ [NC]\n")
  fh:write("        RewriteRule ^/", string.gsub(opts.webstats.path, "%.", "\\."), "/(.*) ", opts.path, "/stats/$1 [L]\n")
  fh:write("        <Directory \"" .. opts.path .. "/stats/\">\n")
  fh:write("            AuthType Basic\n")
  fh:write("            AuthName \"Web Statistics\"\n")
  fh:write("            AuthUserFile \"" .. opts.path .. "/stats/.htpasswd\"\n")
  fh:write("            AuthGroupFile /dev/null\n")
  fh:write("            Require valid-user\n")
  fh:write("            Order allow,deny\n")
  fh:write("            allow from all\n")
  fh:write("        </Directory>\n\n")

  -- create path for stats
  if not LC.fs.is_dir(opts.path .. "/stats") then
    LC.fs.mkdir(opts.path .. "/stats")
    LC.fs.setperm(opts.path .. "/stats", 750, cfg["httpd_user"], opts.group)
    -- set SELinux permissions
    if LC.distribution.family == "RedHat" then
      os.execute("chcon --type=user_home_t \"" .. opts.path .. "/stats\"")
    end
  end

  -- create/update password file
  if opts.webstats.user and opts.webstats.password then
    local pfh, msg = io.open(opts.path .. "/stats/.htpasswd", "w")
    if pfh == nil then
      LC.log.print(LC.log.ERR, "Can't open '", opts.path .. "/stats/.htpasswd", "' for writing: ", msg)
    else
      pfh:write(opts.webstats.user .. ":" .. LC.crypt.crypt(opts.webstats.password) .. "\n")
      pfh:close()
      LC.fs.setperm(opts.path .. "/stats/.htpasswd", 440, cfg["httpd_user"], opts.group)
    end
    -- set SELinux permissions
    if LC.distribution.family == "RedHat" then
      os.execute("chcon --type=httpd_config_t \"" .. opts.path .. "/stats/.htpasswd\"")
    end
  end
end

-- ---------------------------------------------------------------------------
local function writeVHostRedirects(fh, r301, r302, prx)
  -- create RewriteRules for all domains with 301-redirects
  for key in pairs(r301) do
    -- fh:write("... ", key, "...\n")
    if key ~= "" then
      local d
      for i, d in ipairs(r301[key]) do
        d = string.gsub(d, "%.", "\\.")
        d = string.gsub(d, "%*\\%.", "(.+\\.)*")
        fh:write("        RewriteCond %{HTTP_HOST} ^", d, "$ [NC")
        if i < #r301[key] then fh:write(",OR") end
        fh:write("]\n")
      end
      fh:write("        RewriteRule ^/.*         ", string.gsub(key, " ", "\\ "), " [R=301,L]\n\n")
    end
  end

  -- create RewriteRules for all domains with 302-redirects
  for key in pairs(r302) do
    -- fh:write("... ", key, "...\n")
    if key ~= "" then
      local d
      for i, d in ipairs(r302[key]) do
        d = string.gsub(d, "%.", "\\.")
        d = string.gsub(d, "%*\\%.", "(.+\\.)*")
        fh:write("        RewriteCond %{HTTP_HOST} ^", d, "$ [NC")
        if i < #r302[key] then fh:write(",OR") end
        fh:write("]\n")
      end
      fh:write("        RewriteRule ^/.*         ", string.gsub(key, " ", "\\ "), " [R=302,L]\n\n")
    end
  end

  -- create RewriteRules for all domains with proxy destinations
  local prx_count = 0
  local ssl_dest = false
  for key in pairs(prx) do
    -- fh:write("... ", key, "...\n")
    if prx_count == 0 then
      fh:write("      <IfModule mod_proxy.c>\n\n")
    end
    prx_count = prx_count + 1
    if key ~= "" then
      local d
      for i, d in ipairs(prx[key]) do
        d = string.gsub(d, "%.", "\\.")
        d = string.gsub(d, "%*\\%.", "(.+\\.)*")
        fh:write("        RewriteCond %{HTTP_HOST} ^", d, "$ [NC")
        if i < #prx[key] then fh:write(",OR") end
        fh:write("]\n")
      end
      fh:write("        RewriteRule ^(.*)        ", string.gsub(key, " ", "\\ "), "$1 [P,L]\n\n")
      if string.match(key, "^https://") then ssl_dest = true end
    end
  end
  if prx_count > 0 then
    if ssl_dest then
      fh:write("        <IfModule mod_ssl.c>\n")
      fh:write("          SSLProxyEngine On\n")
      fh:write("        </IfModule>\n")
    end
    fh:write("      </IfModule>\n\n")
  end
end

-- ---------------------------------------------------------------------------
-- Build <VirtualHost> sections (called by configureVHost())
-- ---------------------------------------------------------------------------
local function buildConfig(fh, cfg, opts, vhost, domains)
  local cnames = { }
  -- copy all domain names in a table, and then sort them:
  local sd   = { }  -- list with all domains/subdomains and their destination directory
  local sd_count = 0
  local r301 = { }  -- list with all domains/subdomains with 301-redirect
  local r301_count = 0
  local r302 = { }  -- list with all domains/subdomains with 302-redirect
  local r302_count = 0
  local prx  = { }  -- list with all domains/subdomains with proxy destination
  local prx_count = 0   -- Lua doesn't support counting table entries with non-integer keys :(
  local app  = { }  -- list with all domains/subdomains with web application
  local app_count = 0
  local idx, domain, i, key
  for idx, domain in pairs(domains) do

    local dst = vhost.domains[domain].dest
    if dst == nil then dst = '' end

    if vhost.domains[domain].type == 1 then
      -- normal (local) (sub)domain
      if sd[dst] == nil then sd[dst] = { } end
      sd[dst][#sd[dst] + 1] = domain
      sd_count = sd_count + 1
    end

    if vhost.domains[domain].type == 2 then
      -- (sub)domain with 301-redirect
      if r301[dst] == nil then r301[dst] = { } end
      r301[dst][#r301[dst] + 1] = domain
      r301_count = r301_count + 1
    end

    if vhost.domains[domain].type == 3 then
      -- (sub)domain with 302-redirect
      if r302[dst] == nil then r302[dst] = { } end
      r302[dst][#r302[dst] + 1] = domain
      r302_count = r302_count + 1
    end

    if vhost.domains[domain].type == 4 then
      -- (sub)domain with proxy destination
      if prx[dst] == nil then prx[dst] = { } end
      prx[dst][#prx[dst] + 1] = domain
      prx_count = prx_count + 1
    end

    if vhost.domains[domain].type == 5 then
      -- (sub)domain with web application
      if app[dst] == nil then app[dst] = { } end
      app[dst][#app[dst] + 1] = domain
      app_count = app_count + 1
    end

  end

  if string.match(domains[1], "^%*%.") then
    domains[#domains + 1] = domains[1]
    domains[1] = "_catchall_." .. string.sub(domains[1], 3)
  end

  if vhost.ssl then
    fh:write("<IfModule mod_ssl.c>\n")
  end

  if opts.suspended then
    -- website has been suspended
    writeVHostIPs(fh, vhost)

    for idx, domain in ipairs(domains) do
      if idx == 1 then
        fh:write("    ServerName ", domain, "\n")
        cnames[#cnames+1] = domain
      else
        fh:write("    ServerAlias ", domain, "\n")
      end
    end
    fh:write("\n")

    if vhost.ssl then
      writeVHostSSL(fh, cfg, vhost)
    end

    fh:write("    <IfModule mod_rewrite.c>\n")
    fh:write("        RewriteEngine On\n")
    fh:write("        RewriteRule ^/\.errorFiles/.* - [L]\n")
    fh:write("        RewriteRule .* /.errorFiles/suspended.html [R=503,L]\n")
    fh:write("    </IfModule>\n\n")
    fh:write("    ErrorDocument 503 /.errorFiles/suspended.html\n\n")
    fh:write("</VirtualHost>\n")

  elseif CONFIGMODE == 'rewrite' then
    -- Configure all domains/subdomains of a subscription within one single <VirtualHost>
    -- statement. This provides best performance when managing a very large number of
    -- subscriptions and domains on a single machine.
    writeVHostIPs(fh, vhost)

    for idx, domain in ipairs(domains) do
      if idx == 1 then
        fh:write("    ServerName ", domain, "\n")
        cnames[#cnames+1] = domain
      else
        fh:write("    ServerAlias ", domain, "\n")
      end
    end
    fh:write("\n")

    if vhost.ssl then
      writeVHostSSL(fh, cfg, vhost)
    end

    if opts.path then
      writeVHostDocRoot(fh, cfg, opts, vhost, opts.path .. "/" .. LC.web.HTDOCS_PATH)
    end

    -- enable RewriteEngine
    fh:write("    <IfModule mod_rewrite.c>\n")
    fh:write("        RewriteEngine On\n\n")

    if opts.hasCGI then
      -- don't rewrite CGI URLs (if user has CGI permission)
      if LC.distribution.family == "SUSE" then
        -- SUSE has its own /error/ alias - keep it untouched:
        fh:write("        # Don't rewrite /cgi-bin/, /error/, /icons/ and /.errorFiles/ URLs:\n")
        fh:write("        RewriteRule ^/(cgi-bin|error|icons|\.errorFiles)/.* - [L]\n\n")
      else
        fh:write("        # Don't rewrite /cgi-bin/, /icons/ and /.errorFiles/ URLs:\n")
        fh:write("        RewriteRule ^/(cgi-bin|icons|\.errorFiles)/.* - [L]\n\n")
      end
    else
      if LC.distribution.family == "SUSE" then
        -- SUSE has its own /error/ alias - keep it untouched:
        fh:write("        # Don't rewrite /error/, /icons/ and /.errorFiles/ URLs:\n")
        fh:write("        RewriteRule ^/(error|icons|\.errorFiles)/.* - [L]\n\n")
      else
        fh:write("        # Don't rewrite /icons/ and /.errorFiles/ URLs:\n")
        fh:write("        RewriteRule ^/(icons|\.errorFiles)/.* - [L]\n\n")
      end
    end

    -- Web statistics:
    if opts.webstats and opts.webstats.domain and opts.webstats.path and vhost.domains[opts.webstats.domain] ~= nil then
      writeVHostStats(fh, cfg, opts)
    end

    -- create RewriteRules for all domains pointing to a path within DocumentRoot
    for key in pairs(sd) do
      -- fh:write("... ", key, "...\n")
      if key ~= "" then
        local d
        for i, d in ipairs(sd[key]) do
          d = string.gsub(d, "%.", "\\.")
          d = string.gsub(d, "%*\\%.", "(.+\\.)*")
          fh:write("        RewriteCond %{HTTP_HOST} ^", d, "$ [NC")
          if i < #sd[key] then fh:write(",OR") end
          fh:write("]\n")
        end
        fh:write("        RewriteRule ^/(.*)       ", string.gsub(opts.path .. "/" .. LC.web.HTDOCS_PATH .. "/" .. key, " ", "\\ "), "/$1 [L]\n\n")
      end
    end

    writeVHostRedirects(fh, r301, r302, prx)

    -- create RewriteRules for all domains pointing to a web application:
    if app_count > 0 then
      -- allow access to apps directories:
      fh:write("        <Directory \"", opts.path, "/apps\">\n")
      fh:write("            Options SymLinksIfOwnerMatch MultiViews")
      if opts.hasCGI and opts.hasSSI then
        fh:write(" Includes")
      elseif opts.hasSSI then
        fh:write(" IncludesNOEXEC")
      end
      fh:write("\n")
      fh:write("            AllowOverride AuthConfig FileInfo Indexes Limit Options=Indexes,MultiViews\n")
      fh:write("            Order allow,deny\n")
      fh:write("            allow from all\n")
      fh:write("        </Directory>\n\n")

      -- add RewriteRules for apps:
      for key in pairs(app) do
        -- fh:write("... ", key, "...\n")
        if key ~= "" then
          local d
          for i, d in ipairs(app[key]) do
            d = string.gsub(d, "%.", "\\.")
            d = string.gsub(d, "%*\\%.", "(.+\\.)*")
            fh:write("        RewriteCond %{HTTP_HOST} ^", d, "$ [NC")
            if i < #app[key] then fh:write(",OR") end
            fh:write("]\n")
          end
          fh:write("        RewriteRule ^/(.*)       ", string.gsub(opts.path .. "/apps/" .. key, " ", "\\ "), "/$1 [L]\n\n")
        end
      end
    end

    fh:write("    </IfModule>\n\n")

    -- add support for nice default error pages
    fh:write([[
        <LocationMatch "^/$">
            ErrorDocument 403 /.errorFiles/coming-soon.html
            ErrorDocument 404 /.errorFiles/coming-soon.html
        </LocationMatch>

  ]])

    -- include custom configuration options
    if LC.fs.is_file(opts.path .. "/.httpd.conf") then
      fh:write("    # Include customer-specific configuration options:\n")
      fh:write("    Include ", opts.path, "/.httpd.conf\n\n")
    end

    fh:write("</VirtualHost>\n")

  elseif CONFIGMODE == 'virtualhost' then
    -- Configure each different domain/subdomain with own <VirtualHost> statement
    -- This provides best compatibility, especially regarding usage of the
    -- DOCUMENT_ROOT environment variable in PHP/CGI scripts

    -- Step 1: configure all local webspace domains:
    if sd_count > 0 then
      for i in pairs(sd) do
        writeVHostIPs(fh, vhost)

        table.sort(sd[i])
        if string.match(sd[i][1], "^%*%.") then
          sd[i][#sd[i] + 1] = sd[i][1]
          sd[i][1] = "_catchall_." .. string.sub(sd[i][1], 3)
        end

        local d
        for d in pairs(sd[i]) do
          if d == 1 then
            fh:write("    ServerName ", sd[i][d], "\n")
            cnames[#cnames+1] = sd[i][d]
          else
            fh:write("    ServerAlias ", sd[i][d], "\n")
          end
        end
        fh:write("\n")

        if vhost.ssl then
          writeVHostSSL(fh, cfg, vhost)
        end

        if opts.path then
          writeVHostDocRoot(fh, cfg, opts, vhost, opts.path .. "/" .. LC.web.HTDOCS_PATH .. "/" .. i)
        end

        -- enable RewriteEngine
        fh:write("    <IfModule mod_rewrite.c>\n")
        fh:write("        RewriteEngine On\n\n")

        -- Web statistics:
        if opts.webstats and opts.webstats.domain and opts.webstats.path and LC.liveconfig.inTable(opts.webstats.domain, sd) ~= nil then
          writeVHostStats(fh, cfg, opts)
        end

        if i == "" or i == "/" then
          -- add support for nice default error pages (only for domains configured in webspace root directory!)
          fh:write([[
        <LocationMatch "^/$">
            ErrorDocument 403 /.errorFiles/coming-soon.html
            ErrorDocument 404 /.errorFiles/coming-soon.html
        </LocationMatch>

  ]])
        end

        fh:write("    </IfModule>\n\n") -- mod_rewrite.c

        -- include custom configuration options
        if LC.fs.is_file(opts.path .. "/.httpd.conf") then
          fh:write("    # Include customer-specific configuration options:\n")
          fh:write("    Include ", opts.path, "/.httpd.conf\n\n")
        end

        fh:write("</VirtualHost>\n")

      end
    end -- sd_count > 0

    -- Step 2: configure all redirects:
    if r301_count > 0 or r302_count > 0 or prx_count > 0 then
      -- create table "dl" containing all domains with 301/302/PROXY redirect
      -- so we can configure all of them together in one single <VirtualHost>
      local dl = { }
      local j
      for i in pairs(r301) do
        for j in pairs(r301[i]) do
          dl[#dl + 1] = r301[i][j]
        end
      end
      for i in pairs(r302) do
        for j in pairs(r302[i]) do
          dl[#dl + 1] = r302[i][j]
        end
      end
      for i in pairs(prx) do
        for j in pairs(prx[i]) do
          dl[#dl + 1] = prx[i][j]
        end
      end

      writeVHostIPs(fh, vhost)

      table.sort(dl)
      if string.match(dl[1], "^%*%.") then
        dl[#dl + 1] = dl[1]
        dl[1] = "_catchall_." .. string.sub(dl[1], 3)
      end

      for i in pairs(dl) do
        if i == 1 then
          fh:write("    ServerName ", dl[i], "\n")
          cnames[#cnames+1] = dl[i]
        else
          fh:write("    ServerAlias ", dl[i], "\n")
        end
      end
      fh:write("\n")

      if vhost.ssl then
        writeVHostSSL(fh, cfg, vhost)
      end

      -- enable RewriteEngine
      fh:write("    <IfModule mod_rewrite.c>\n")
      fh:write("        RewriteEngine On\n\n")

      -- Web statistics:
      if opts.webstats and opts.webstats.domain and opts.webstats.path and LC.liveconfig.inTable(opts.webstats.domain, dl) ~= nil then
        writeVHostStats(fh, cfg, opts)
      end

      writeVHostRedirects(fh, r301, r302, prx)

      fh:write("    </IfModule>\n\n") -- mod_rewrite.c

      -- include custom configuration options
      if LC.fs.is_file(opts.path .. "/.httpd.conf") then
        fh:write("    # Include customer-specific configuration options:\n")
        fh:write("    Include ", opts.path, "/.httpd.conf\n\n")
      end

      fh:write("</VirtualHost>\n")
    end -- r301_count > 0 or r302_count > 0 or prx_count > 0

    -- Step 3: configure all domains pointing to a web application:
    if app_count > 0 then
      for i in pairs(app) do

        writeVHostIPs(fh, vhost)

        table.sort(app[i])
        if string.match(app[i][1], "^%*%.") then
          app[i][#app[i] + 1] = app[i][1]
          app[i][1] = "_catchall_." .. string.sub(app[i][1], 3)
        end

        local d
        for d in pairs(app[i]) do
          if d == 1 then
            fh:write("    ServerName ", app[i][d], "\n")
            cnames[#cnames+1] = app[i][d]
          else
            fh:write("    ServerAlias ", app[i][d], "\n")
          end
        end
        fh:write("\n")

        if vhost.ssl then
          writeVHostSSL(fh, cfg, vhost)
        end

        if opts.path then
          writeVHostDocRoot(fh, cfg, opts, vhost, opts.path .. "/apps/" .. i)
        end

        -- enable RewriteEngine
        fh:write("    <IfModule mod_rewrite.c>\n")
        fh:write("        RewriteEngine On\n\n")

        -- Web statistics:
        if opts.webstats and opts.webstats.domain and opts.webstats.path and LC.liveconfig.inTable(opts.webstats.domain, sd) ~= nil then
          writeVHostStats(fh, cfg, opts)
        end

        fh:write("    </IfModule>\n\n") -- mod_rewrite.c

        -- include custom configuration options
        if LC.fs.is_file(opts.path .. "/.httpd.conf") then
          fh:write("    # Include customer-specific configuration options:\n")
          fh:write("    Include ", opts.path, "/.httpd.conf\n\n")
        end

        fh:write("</VirtualHost>\n")

      end
    end -- app_count > 0

  else
    fh:write("# Unknown configuration mode '", CONFIGMODE, "'!")
  end

  if vhost.ssl then
    fh:write("</IfModule>\n")
  end

  -- return array with canonical server names
  return cnames
end

-- ---------------------------------------------------------------------------
-- configureVHost(cfg, opts)
--
-- Configure virtual host for Apache httpd
-- ---------------------------------------------------------------------------
function configureVHost(cfg, opts)

  LC.log.print(LC.log.DEBUG, "configureVHost(apache) called")

  local vhostpath  = cfg["available_dir"] or cfg["enabled_dir"]
  if opts and opts.prefix then vhostpath = opts.prefix .. vhostpath end -- use prefix (for testing etc.)
  local filename = vhostpath .. "/" .. opts["name"] .. ".conf"
  local tempfile = filename .. ".tmp"
--  tempfile = "/tmp/test.conf"
  local i = 0
  local key
  local cnames = {}     -- canonical ServerName list (required for lclogsplit map entry!)

  if LC.fs.is_file(filename .. ".lock") then
    -- don't modify configuration
    LC.log.print(LC.log.INFO, "Not modifying ", filename, ": configuration locked")
    return true
  end

  -- create temporary config file
  local fh, msg = io.open(tempfile, "w")
  if fh == nil then
    LC.log.print(LC.log.ERR, "Can't open '", tempfile, "' for writing: ", msg)
    return false, "Can't open '" .. tempfile .. "' for writing: " .. msg
  end
  LC.liveconfig.writeHeader(fh)
  fh:write("# Automatically created by LiveConfig - do not modify!\n")
  fh:write("# Created at: ", os.date("%Y-%m-%d %H:%M:%S %Z"), "\n")
  fh:write("# ----------------------------------------------------------------------------\n\n")

  -- now check every single vhost, configure it if it's for this server:
  local vhostIdx
  if type(opts.vhosts) == "table" then
    -- create all VirtualHost sections for regular (non-wildcard) domains:
    for vhostIdx=1, #opts.vhosts do
      while opts.vhosts[vhostIdx].server == cfg.type do
        local vhost = opts.vhosts[vhostIdx]

        fh:write("# IP group: '", vhost.ipgroup, "'\n")
        if vhost.ips == nil then
          fh:write("# -> no IPs configured!\n")
          break
        end

        local dn = { }  -- list with all regular domain names
        for key in pairs(vhost.domains) do
          if not string.match(key, "^%*%.") then
            dn[#dn + 1] = key
          end
        end
        table.sort(dn)

        local cn
        -- configure all regular domains
        if #dn > 0 then
          cn = buildConfig(fh, cfg, opts, vhost, dn)
          for i, key in pairs(cn) do cnames[#cnames + 1] = key end
        end

        fh:write("\n")

        break -- leave 'while(true)' loop
      end -- while...
    end -- for...

    -- create all VirtualHost sections for wildcard domains:
    for vhostIdx=1, #opts.vhosts do
      while opts.vhosts[vhostIdx].server == cfg.type do
        local vhost = opts.vhosts[vhostIdx]

        fh:write("# IP group: '", vhost.ipgroup, "'\n")
        if vhost.ips == nil then
          fh:write("# -> no IPs configured!\n")
          break
        end

        local wc = { }  -- list with all wildcard domain names
        for key in pairs(vhost.domains) do
          if string.match(key, "^%*%.") then
            wc[#wc + 1] = key
          end
        end
        table.sort(wc)

        local cn
        -- configure all wildcard domains
        if #wc > 0 then
          cn = buildConfig(fh, cfg, opts, vhost, wc)
          for i, key in pairs(cn) do cnames[#cnames + 1] = key end
        end

        fh:write("\n")

        break -- leave 'while(true)' loop
      end -- while...
    end -- for...

  end -- if type(opts.vhosts) == "table"

  -- close (temporary) config file
  LC.liveconfig.writeFooter(fh)
  fh:close()

  -- rename config file (atomic)
  LC.fs.rename(tempfile, filename)

  -- update map file (for lclogsplit)
  updateMapFile(cfg, opts, cnames, opts.path .. "/logs/access.log")

  if #cnames == 0 then
    -- disable configuration, remove config file
    if cfg["disable_cmd"] ~= nil then
      os.execute(cfg["disable_cmd"] .. " " .. opts["name"] .. ".conf")
    end
    os.remove(filename)
    LC.log.print(LC.log.INFO, "Removing '", filename, "' (no vHosts configured)")
  else
    -- if not done yet, enable config
    if cfg["enable_cmd"] ~= nil then
      os.execute(cfg["enable_cmd"] .. " " .. opts["name"] .. ".conf")
    end
  end

  -- reload web server configuration
  LC.timeout.set('apache.reload', 10, 60)

  return true

end

-- ---------------------------------------------------------------------------
-- reload()
--
-- Reload Apache configuration
-- ---------------------------------------------------------------------------
function reload()
  LC.log.print(LC.log.DEBUG, "apache.reload() called")
  -- get configuration
  local cfg = LC.web.getConfig('apache')
  if cfg == nil then
    LC.log.print(LC.log.ERR, "apache.reload(): no configuration for 'apache' available!?")
    return
  end
  -- get reload command
  if cfg.reload_cmd == nil then
    LC.log.print(LC.log.ERR, "apache.reload(): no reload command for 'apache' available!?")
    return
  end

  -- reload service
  os.execute(cfg.reload_cmd)

end

-- ---------------------------------------------------------------------------
-- restart()
--
-- Restart Apache web server
-- ---------------------------------------------------------------------------
function restart()
  LC.log.print(LC.log.DEBUG, "apache.restart() called")
  -- get configuration
  local cfg = LC.web.getConfig('apache')
  if cfg == nil then
    LC.log.print(LC.log.ERR, "apache.restart(): no configuration for 'apache' available!?")
    return
  end
  -- get restart command
  if cfg.restart_cmd == nil then
    LC.log.print(LC.log.ERR, "apache.restart(): no restart command for 'apache' available!?")
    return
  end

  -- restart service
  os.execute(cfg.restart_cmd)

end

-- ---------------------------------------------------------------------------
-- deleteAccount()
--
-- Delete account/vHost
-- ---------------------------------------------------------------------------
function deleteAccount(cfg, name)
  local vhostpath  = cfg["available_dir"] or cfg["enabled_dir"]
  local filename = vhostpath .. "/" .. name .. ".conf"

  LC.log.print(LC.log.DEBUG, "apache.deleteAccount(", name, ") (config file: '", filename, "'")

  updateMapFile(cfg, nil, {}, LC.web.getWebRoot() .. "/" .. name:lower() .. "/logs/access.log")

  if not LC.fs.is_file(filename) then return end

  if cfg["disable_cmd"] ~= nil then
    os.execute(cfg["disable_cmd"] .. " " .. name .. ".conf")
  end
  os.remove(filename)

  -- reload web server configuration
  LC.timeout.set('apache.reload', 10, 60)

end

-- <EOF>----------------------------------------------------------------------
