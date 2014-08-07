--  _    _          ___           __ _     (R)
-- | |  (_)_ _____ / __|___ _ _  / _(_)__ _
-- | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
-- |____|_|\_/\___|\___\___/_||_|_| |_\__, |
--                                    |___/
-- Copyright (c) 2009-2012 Keppler IT GmbH.
-- ---------------------------------------------------------------------------
-- common/lua/nginx.lua
-- Lua module to manage NGINX web server
-- $Id: nginx.lua 2900 2014-06-05 08:19:13Z kk $
-- ---------------------------------------------------------------------------
-- This is the "driver" module for NGINX web server.
-- It must be loaded by the command
--   LC.web.load("nginx")
-- Usually, this should happen at liveconfig.lua (or, if you have a customized
-- module, at custom.lua)
-- ---------------------------------------------------------------------------

-- Imported functions
local LC = LC
local LCS = LCS -- import liveconfig global storage
local type = type
local io = io
local os = os
local ipairs = ipairs
local pairs = pairs
local string = string
local table = table     -- for table.sort
local tonumber = tonumber

-- Module declaration
module("nginx")

-- Exported functions
--   detect()
--   install()
--   uninstall()
--   configure()
--   configureVHost()
--   reload()
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
-- Return the binary version number from NGINX
-- ---------------------------------------------------------------------------
local function getBinaryVersion(bin)
  local handle = io.popen(bin .. " -v 2>&1", "r")
  local ret = handle:read("*a")
  handle:close()
  local v = string.match(ret, "nginx/(%d+%.%d+[%.%d+]*)")
  return v
end

-- ---------------------------------------------------------------------------
-- detect()
--
-- Detect if NGINX is installed. If yes, return a table containing
-- all relevant informations:
--   type          => "nginx"
--   binname       => file name of the NGINX binary (eg. "/usr/sbin/nginx")
--   binversion    => binary version (eg. "0.6.32")
--   pkgname       => name of the package (see below)
--   pkgversion    => package version number (eg. "0.6.32-3+lenny3")
--   configpath    => Main configuration path for NGINX
--   configfile    => LiveConfigs' configuration file (snippet)
--   statusfile    => LiveConfigs' status file (containing config version etc.)
--   defaultlog    => Default log file (for default and unknown/unconfigured vhosts)
--   start_cmd     => command to start NGINX
--   stop_cmd      => command to stop NGINX
--   reload_cmd    => command to re-load configuration
--   restart_cmd   => command to re-start NGINX process
--   available_dir => path for all available vhost configuration files
--   enabled_dir   => path for enabled vhost configuration files
--   enable_cmd    => command to enable a vhost configuration file (eg. "/usr/sbin/a2ensite")
--   disable_cmd   => command to disable a vhost configuration file (eg. "/usr/sbin/a2dissite")
--   httpd_user    => user running NGINX
--   httpd_group   => group running NGINX
--
-- If pkgversion is 'nil', then NGINX was most propably not installed
-- as native distribution package, but compiled/installed manually.
-- ---------------------------------------------------------------------------
function detect()

  -- first check for distribution-specific packages
  if LC.distribution.family == "Debian" then
    -- Debian/Ubuntu
    -- Package is named "nginx"
    local pkg, v = LC.distribution.hasPackage('nginx', 'nginx-full', 'nginx-light', 'nginx-naxsi', 'nginx-extras')
    if pkg ~= nil then
      LC.log.print(LC.log.DEBUG, "Found package '", pkg, "' (Version ", v, ")")
      local bin = "/usr/sbin/nginx"
      -- get binary version
      local bv = getBinaryVersion(bin)
      LC.log.print(LC.log.DEBUG, "binver ", bv)
      if bv ~= nil then
        -- ok, we have all informations. return data table:
        local data = {
          ["type"]          = "nginx",
          ["binname"]       = bin,
          ["binversion"]    = bv,
          ["pkgname"]       = pkg,
          ["pkgversion"]    = v,
          ["configpath"]    = "/etc/nginx",
          ["configfile"]    = "/etc/nginx/conf.d/liveconfig.conf",
          ["statusfile"]    = "/etc/nginx/liveconfig.status",
          ["defaultlog"]    = "/var/log/nginx/default_vhost.log",
          ["start_cmd"]     = "/etc/init.d/nginx start",
          ["stop_cmd"]      = "/etc/init.d/nginx stop",
          ["reload_cmd"]    = "/etc/init.d/nginx reload",
          ["restart_cmd"]   = "/etc/init.d/nginx restart",
          ["available_dir"] = "/etc/nginx/sites-available",
          ["enabled_dir"]   = "/etc/nginx/sites-enabled",
          ["enable_cmd"]    = nil,
          ["disable_cmd"]   = nil,
          ["httpd_user"]    = "www-data",
          ["httpd_group"]   = "www-data",
          ["has_sni"]       = true,
          ["ssl_cert_dir"]  = "/etc/ssl/certs",
          ["ssl_key_dir"]   = "/etc/ssl/private",
          ["ssl_key_user"]  = "root",
          ["ssl_key_group"] = "ssl-cert",
          ["ssl_key_mode"]  = "0640",
          ["htdocs_path"]   = LC.web.HTDOCS_PATH,
        }
        return data
      end
      -- else: fall trough, to check for custom NGINX installation
      LC.log.print(LC.log.DEBUG, "LC.nginx.detect(): Found NGINX package '", pkg, "', but no binary at ", bin)
    end
  elseif LC.distribution.family == "Gentoo" then
    -- Debian/Ubuntu
    -- Package is named "nginx"
    local pkg, v = LC.distribution.hasPackage( 'nginx')
    if pkg ~= nil then
      LC.log.print(LC.log.DEBUG, "Found package '", pkg, "' (Version ", v, ")")
      local bin = "/usr/sbin/nginx"
      -- get binary version
      local bv = getBinaryVersion(bin)
      LC.log.print(LC.log.DEBUG, "binver ", bv)
      if bv ~= nil then
        -- ok, we have all informations. return data table:
        local data = {
          ["type"]          = "nginx",
          ["binname"]       = bin,
          ["binversion"]    = bv,
          ["pkgname"]       = pkg,
          ["pkgversion"]    = v,
          ["configpath"]    = "/etc/nginx",
          ["configfile"]    = "/etc/nginx/conf.d/liveconfig.conf",
          ["statusfile"]    = "/etc/nginx/liveconfig.status",
          ["defaultlog"]    = "/var/log/nginx/default_vhost.log",
          ["start_cmd"]     = "/etc/init.d/nginx start",
          ["stop_cmd"]      = "/etc/init.d/nginx stop",
          ["reload_cmd"]    = "/etc/init.d/nginx reload",
          ["restart_cmd"]   = "/etc/init.d/nginx restart",
          ["available_dir"] = "/etc/nginx/sites-available",
          ["enabled_dir"]   = "/etc/nginx/sites-enabled",
          ["enable_cmd"]    = nil,
          ["disable_cmd"]   = nil,
          ["httpd_user"]    = "nginx",
          ["httpd_group"]   = "nginx",
          ["has_sni"]       = true,
          ["ssl_cert_dir"]  = "/etc/ssl/certs",
          ["ssl_key_dir"]   = "/etc/ssl/private",
          ["ssl_key_user"]  = "root",
          ["ssl_key_group"] = "root",
          ["ssl_key_mode"]  = "0640",
          ["htdocs_path"]   = LC.web.HTDOCS_PATH,
        }
        return data
      end
      -- else: fall trough, to check for custom NGINX installation
      LC.log.print(LC.log.DEBUG, "LC.nginx.detect(): Found NGINX package '", pkg, "', but no binary at ", bin)
    end
  elseif LC.distribution.family == "SUSE" then
    -- OpenSUSE
    -- Package is named "nginx"
    local pkg, v = LC.distribution.hasPackage( 'nginx')
    if pkg ~= nil then
      LC.log.print(LC.log.DEBUG, "Found package '", pkg, "' (Version ", v, ")")
      local bin = "/usr/sbin/nginx"
      -- get binary version
      local bv = getBinaryVersion(bin)
      LC.log.print(LC.log.DEBUG, "binver ", bv)
      if bv ~= nil then
        -- ok, we have all informations. return data table:
        local data = {
          ["type"]          = "nginx",
          ["binname"]       = bin,
          ["binversion"]    = bv,
          ["pkgname"]       = pkg,
          ["pkgversion"]    = v,
          ["configpath"]    = "/etc/nginx",
          ["configfile"]    = "/etc/nginx/conf.d/liveconfig.conf",
          ["statusfile"]    = "/etc/nginx/liveconfig.status",
          ["defaultlog"]    = "/var/log/nginx/access.log",
          ["start_cmd"]     = "/etc/init.d/nginx start",
          ["stop_cmd"]      = "/etc/init.d/nginx stop",
          ["reload_cmd"]    = "/etc/init.d/nginx reload",
          ["restart_cmd"]   = "/etc/init.d/nginx restart",
--          ["available_dir"] = "/etc/nginx/sites-available",
          ["enabled_dir"]   = "/etc/nginx/vhosts.d",
          ["enable_cmd"]    = nil,
          ["disable_cmd"]   = nil,
          ["httpd_user"]    = "www-data",
          ["httpd_group"]   = "www-data",
          ["has_sni"]       = true,
          ["ssl_cert_dir"]  = "/etc/nginx/ssl",
          ["ssl_key_dir"]   = "/etc/nginx/ssl",
          ["ssl_key_user"]  = "root",
          ["ssl_key_group"] = "root",
          ["ssl_key_mode"]  = "0600",
          ["htdocs_path"]   = LC.web.HTDOCS_PATH,
        }
        return data
      end
      -- else: fall trough, to check for custom NGINX installation
      LC.log.print(LC.log.DEBUG, "LC.nginx.detect(): Found NGINX package '", pkg, "', but no binary at ", bin)
    end
  elseif LC.distribution.family == "RedHat" then
    -- RedHat/CentOS
    -- Package is named "nginx", available at http://nginx.org/packages/centos/
    local pkg, v = LC.distribution.hasPackage('nginx')
    if pkg ~= nil then
      LC.log.print(LC.log.DEBUG, "Found package '", pkg, "' (Version ", v, ")")
      local bin = "/usr/sbin/nginx"
      -- get binary version
      local bv = getBinaryVersion(bin)
      LC.log.print(LC.log.DEBUG, "binver ", bv)
      if bv ~= nil then
        -- ok, we have all informations. return data table:
        local data = {
          ["type"]          = "nginx",
          ["binname"]       = bin,
          ["binversion"]    = bv,
          ["pkgname"]       = pkg,
          ["pkgversion"]    = v,
          ["configpath"]    = "/etc/nginx",
          ["configfile"]    = "/etc/nginx/conf.d/liveconfig.conf",
          ["statusfile"]    = "/etc/nginx/liveconfig.status",
          ["defaultlog"]    = "/var/log/nginx/access.log",
          ["start_cmd"]     = "/sbin/service nginx start",
          ["stop_cmd"]      = "/sbin/service nginx stop",
          ["reload_cmd"]    = "/sbin/service nginx reload",
          ["restart_cmd"]   = "/sbin/service nginx restart",
--          ["available_dir"] = "/etc/nginx/sites-available",
          ["enabled_dir"]   = "/etc/nginx/vhosts.d",
          ["enable_cmd"]    = nil,
          ["disable_cmd"]   = nil,
          ["httpd_user"]    = "apache",
          ["httpd_group"]   = "apache",
          ["has_sni"]       = true,
          ["ssl_cert_dir"]  = "/etc/pki/tls/certs",
          ["ssl_key_dir"]   = "/etc/pki/tls/private",
          ["ssl_key_user"]  = "root",
          ["ssl_key_group"] = "root",
          ["ssl_key_mode"]  = "0600",
          ["htdocs_path"]   = LC.web.HTDOCS_PATH,
        }
        return data
      end
      -- else: fall trough, to check for custom NGINX installation
      LC.log.print(LC.log.DEBUG, "LC.nginx.detect(): Found NGINX package '", pkg, "', but no binary at ", bin)
    end
  end  
end

-- ---------------------------------------------------------------------------
-- install(cfg, opts)
--
-- Install LiveConfig configuration files for NGINX
-- ---------------------------------------------------------------------------
function install(cfg, opts)
  LC.log.print(LC.log.INFO, "Activating management of NGINX")

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

  -- create directory for liveconfig.conf:
  if not LC.fs.is_dir(configpath .. "/conf.d") then
    LC.fs.mkdir(configpath .. "/conf.d")
    LC.fs.setperm(configpath .. "/conf.d", 755, "root", "root")
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
# We define our own log format here, containing the "canonical" server name

log_format LiveConfig '$server_name:#:$remote_addr - $remote_user [$time_local] '
                      '"$request" $status $body_bytes_sent '
                      '"$http_referer" "$http_user_agent" $request_length $bytes_sent';

]])

  if LC.distribution.family == "RedHat" then
    fh:write([[
# Virtual Hosts configuration
include /etc/nginx/vhosts.d/*;

]])
    if LC.fs.is_file("/etc/nginx/conf.d/default.conf") then
      -- move away default.conf, as this contains a "listen" command:
      LC.fs.rename("/etc/nginx/conf.d/default.conf", "/etc/nginx/conf.d/default.conf.lcbak")
    end
  end

  -- write footer
  LC.liveconfig.writeFooter(fh)

  fh:close()

  -- create directory for vhosts:
  if not LC.fs.is_dir(vhostpath) then
    LC.fs.mkdir(vhostpath)
    LC.fs.setperm(vhostpath, 750, "root", cfg.httpd_group)
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
    fh:write("default ", cfg.defaultlog, "\n")
    LC.liveconfig.writeFooter(fh)
    fh:close()
  end

  if LC.distribution.family == "Debian" then
    vhostfile = "default"
  elseif LC.distribution.family == "Gentoo" then
    vhostfile = "default"
  elseif LC.distribution.family == "SUSE" then
    -- ###TODO### replace nginx.conf (this creates a default server we don't want)
    vhostfile = "default.conf"
  elseif LC.distribution.family == "RedHat" then
    vhostfile = "default.conf"
  else
    LC.log.print(LC.log.ERR, "Distribution family '", LC.distribution.family, "' not supported (yet)")
    return false, "Distribution family '" .. LC.distribution.family .. "' not supported (yet)"
  end

  -- back up old default vhost file (if existing)
  if LC.fs.is_file(vhostpath .. "/" .. vhostfile) and not LC.fs.is_file(vhostpath .. "/" .. vhostfile .. ".lcbak") then
    LC.fs.rename(vhostpath .. "/" .. vhostfile, vhostpath .. "/" .. vhostfile .. ".lcbak")
  end

  -- write default vhost file:
  configure(cfg, opts)

  -- install init script for controlling PHP-FCGI instances
  if not LC.fs.is_file("/etc/init.d/nginx-php-fcgi") then
    os.execute("ln -s /usr/lib/liveconfig/nginx-php-fcgi /etc/init.d/nginx-php-fcgi")
    if LC.fs.is_file("/sbin/insserv") then
      os.execute("/sbin/insserv nginx-php-fcgi")
    elseif LC.fs.is_file("/sbin/chkconfig") then
      os.execute("/sbin/chkconfig --add nginx-php-fcgi")
    elseif LC.fs.is_file("/sbin/rc-update") then
      os.execute("/sbin/rc-update add nginx-php-fcgi default")
    else
      LC.log.print(LC.log.ERR, "Can't install init script 'nginx-php-fcgi' - no supported tool found")
    end
  end

  -- write status file
  LC.liveconfig.writeStatus(statusfile, cfg.type, 0, os.date("%Y-%m-%d %H:%M:%S %Z"))

  return true
end

-- ---------------------------------------------------------------------------
-- uninstall(cfg, opts)
--
-- Remove LiveConfig configuration files from NGINX
-- ---------------------------------------------------------------------------
function uninstall(cfg, opts)
  LC.log.print(LC.log.INFO, "Disabling management of NGINX")

  local status, msg
  local configpath = cfg["configpath"]
  local configfile = cfg["configfile"]
  local statusfile = cfg["statusfile"]

  if opts and opts.prefix then
    -- use prefix (for testing etc.)
    configpath = opts.prefix .. configpath
    configfile = opts.prefix .. configfile
    statusfile = opts.prefix .. statusfile
  end

  if LC.distribution.family == "Debian" then
  elseif LC.distribution.family == "Gentoo" then
  elseif LC.distribution.family == "SUSE" then
  else
    LC.log.print(LC.log.ERR, "Distribution family '", LC.distribution.family, "' not supported (yet)1")
    return false, "Distribution family '" .. LC.distribution.family .. "' not supported (yet)1"
  end

  -- remove status file
  status, msg = os.remove(statusfile)
  if status == nil then
    return false, LC.log.print(LC.log.ERR, "Deletion of '", statusfile, "' failed: ", msg)
  end

  return true
end


-- ---------------------------------------------------------------------------
-- configure(cfg, opts)
--
-- Configure NGINX
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

  local v_major, v_minor, v_patch = string.match(cfg.binversion, "(%d+)%.(%d+)%.(%d+)")
  v_major = tonumber(v_major)
  v_minor = tonumber(v_minor)

  if LC.distribution.family == "Debian" then
    vhostfile = "default"
  elseif LC.distribution.family == "Gentoo" or LC.distribution.family == "RedHat" then
    vhostfile = "default"
  elseif LC.distribution.family == "SUSE" then
    vhostfile = "default.conf"
  else
    LC.log.print(LC.log.ERR, "Distribution family '", LC.distribution.family, "' not supported (yet)2")
    return false, "Distribution family '" .. LC.distribution.family .. "' not supported (yet)2"
  end

  fh, msg = io.open(vhostpath .. "/" .. vhostfile, "w")
  if fh == nil then
    LC.log.print(LC.log.ERR, "Can't open '", vhostpath .. "/" .. vhostfile, "' for writing: ", msg)
    return false, "Can't open '" .. vhostpath .. "/" .. vhostfile.. "' for writing: " .. msg
  end
  LC.liveconfig.writeHeader(fh)

  if opts.interfaces ~= nil or opts.ssl_interfaces ~= nil then
    fh:write([[
# Default VirtualHost configuration
# Automatically created by LiveConfig

server {
]])

    -- SSL configuration
    if opts.interfaces ~= nil then
      for i=1, #opts.interfaces do
        fh:write("\tlisten\t\t", opts.interfaces[i], ";\n")
      end
    end
    if opts.ssl_interfaces ~= nil then
      for i=1, #opts.ssl_interfaces do
        fh:write("\tlisten\t\t", opts.ssl_interfaces[i], ";\n")
      end
      fh:write("\tssl_prefer_server_ciphers on;\n")
      if opts.ssl_pci then
        fh:write("\tssl_ciphers ", LC.liveconfig.DEFAULT_SSL_PCI_CIPHERS, ";\n")
      else
        fh:write("\tssl_ciphers ", LC.liveconfig.DEFAULT_SSL_CIPHERS, ";\n")
      end
    end

    if v_major == 0 and (v_minor < 8 or (v_minor == 8 and v_patch < 21)) then
      fh:write("\tserver_name\tdefault;\n\n")
    else
      fh:write("\tserver_name\tdefault_server;\n\n")
    end

    fh:write("\troot\t\t/usr/share/liveconfig/html;\n")
    fh:write("\tssi\t\ton;\n")
    fh:write("\terror_page\t\t403 /not-available.shtml;\n")
    fh:write("\terror_page\t\t404 /not-available.shtml;\n")

    if v_major < 1 or (v_major == 1 and v_minor < 5) or (v_major == 1 and v_minor == 5 and v_patch < 7) then
      -- mitigate CVE-2013-4547:
      fh:write("\tif ($request_uri ~ \" \") {\n")
      fh:write("\t\treturn 444;\n")
      fh:write("\t}\n")
    end

    fh:write("\n}\n")
  end

  LC.liveconfig.writeFooter(fh)
  fh:close()

  -- update status file
  LC.liveconfig.writeStatus(statusfile, cfg.type, opts.revision, os.date("%Y-%m-%d %H:%M:%S %Z"))

  -- reload web server configuration
  LC.timeout.set('nginx.reload', 10, 60)

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
      -- get domain part of matched line
      local d = string.match(line, "^[^%s]*")
      if domainlist[d] then
        -- this domain remains in map file (only remove found domain from domainlist)
        domainlist[d] = nil
      else
        -- remove this entry from map file
        line = nil
      end
    end
    if line ~= nil then
      fhw:write(line, "\n")
    end
  end

  for i in pairs(domainlist) do
    -- entry not found, so add new one:
    fhw:write(i, " ", logname, "\n")
  end

  fhw:close()
  fhr:close()

  -- rename map file
  LC.fs.rename(configpath .. "/accesslog.map.tmp", configpath .. "/accesslog.map")

end

-- ---------------------------------------------------------------------------
-- Helper function:
-- ---------------------------------------------------------------------------
local function write_server(cfg, opts, fh, vhost, dom)
  local i, key
  fh:write("server {\n")
  for i, key in ipairs(vhost.ips) do
    fh:write("\tlisten\t\t")
    if vhost.ssl then
      if string.find(key, ":") then
        -- IPv6 address
        fh:write("[", key, "]:443")
      else
        -- IPv4 address
        fh:write(key, ":443")
      end
    else
      if string.find(key, ":") then
        -- IPv6 address
        fh:write("[", key, "]:80")
      else
        -- IPv4 address
        fh:write(key, ":80")
      end
    end
    fh:write(";\n")
  end

  for i, key in ipairs(dom) do
    if i == 1 then
      fh:write("\tserver_name\t")
    else
      fh:write("\n\t\t\t")
    end
    fh:write(key)
--    cnames[#cnames+1] = key
  end
  fh:write(";\n")

  if vhost.ssl then
    -- SSL configuration:
    fh:write("\tssl\t\ton;\n")
--    TLSv1.1 and TLSv1.2 are only supported on OpenSSL 1.0.1+; we'd have to detect this first... :-/
--    fh:write("\tssl_protocols\tSSLv3 TLSv1 TLSv1.1 TLSv1.2;\n")
    fh:write("\tssl_protocols\tSSLv3 TLSv1;\n")
    if vhost.ssl_pci then
      fh:write("\tssl_ciphers\t", LC.liveconfig.DEFAULT_SSL_PCI_CIPHERS, ";\n")
    else
      fh:write("\tssl_ciphers\t", LC.liveconfig.DEFAULT_SSL_CIPHERS, ";\n")
    end

    -- create/update SSL certificate file:
    if not LC.fs.is_dir(cfg.ssl_cert_dir) then
      LC.fs.mkdir(cfg.ssl_cert_dir)
      LC.fs.setperm(cfg.ssl_cert_dir, 755, "root", "root")
    end
    local sfh
    local fname = cfg.ssl_cert_dir .. "/" .. vhost.ssl_filename .. "-combined.crt"
    sfh, msg = io.open(fname, "w")
    if sfh == nil then
      LC.log.print(LC.log.ERR, "Can't open '", fname, "' for writing: ", msg)
      return false, "Can't open '" .. fname .. "' for writing: " .. msg
    end
    sfh:write(vhost.ssl_crt)
    if vhost.ssl_ca ~= nil then
      -- append chained certificates
      sfh:write(vhost.ssl_ca)
    end
    sfh:close()
    LC.fs.setperm(fname, "0644", "root", "root")
    fh:write("\tssl_certificate\t", fname, ";\n")

    -- create/update SSL key file:
    if not LC.fs.is_dir(cfg.ssl_key_dir) then
      LC.fs.mkdir(cfg.ssl_key_dir)
      LC.fs.setperm(cfg.ssl_key_dir, 755, "root", "root")
    end
    fname = cfg.ssl_key_dir .. "/" .. vhost.ssl_filename .. ".key"
    sfh, msg = io.open(fname, "w")
    if sfh == nil then
      LC.log.print(LC.log.ERR, "Can't open '", fname, "' for writing: ", msg)
      return false, "Can't open '" .. fname .. "' for writing: " .. msg
    end
    sfh:write(vhost.ssl_key)
    sfh:close()
    LC.fs.setperm(fname, cfg["ssl_key_mode"], cfg["ssl_key_user"], cfg["ssl_key_group"])
    fh:write("\tssl_certificate_key\t", fname, ";\n")
    fh:write("\n")
  end

  -- Web statistics:
  if opts.webstats and opts.webstats.domain and opts.webstats.path and LC.liveconfig.inTable(opts.webstats.domain, dom) then
    fh:write("\t# Web statistics:\n")
    fh:write("\tlocation /", opts.webstats.path, "/ {\n")
    fh:write("\t\tauth_basic \"Web Statistics\";\n")
    fh:write("\t\tauth_basic_user_file \"", opts.path, "/stats/.htpasswd\";\n")
    fh:write("\t\talias \"", opts.path, "/stats/\";\n")
    fh:write("\t}\n")
    if opts.webstats.software == 1 then
      -- shared resources for Webalizer
      fh:write("\tlocation /", opts.webstats.path, "/images/ {\n")
      fh:write("\t\talias /usr/share/liveconfig/html/webalizer/;\n")
      fh:write("\t}\n")
    elseif opts.webstats.software == 2 then
      -- shared resources for AWStats
      local icondir = "/usr/share/awstats/icon/"
      if LC.distribution.family == "RedHat" then
        icondir = "/var/www/awstats/icon/"
      elseif LC.distribution.family == "SUSE" then
        icondir = "/usr/share/awstats/icon/"
      elseif LC.distribution.family == "Gentoo" then
        icondir = "/usr/share/awstats/wwwroot/icon/"
      end
      fh:write("\tlocation /", opts.webstats.path, "/icon/ {\n")
      fh:write("\t\talias ", icondir, ";\n")
      fh:write("\t}\n")
      fh:write("\tlocation /", opts.webstats.path, "/awstats/ {\n")
      fh:write("\t\talias /usr/share/liveconfig/html/awstats/;\n")
      fh:write("\t}\n")
    end
    fh:write("\n")
  end

end

-- ---------------------------------------------------------------------------
-- configureVHost(cfg, opts)
--
-- Configure virtual host for NGINX
-- ---------------------------------------------------------------------------
function configureVHost(cfg, opts)

  LC.log.print(LC.log.DEBUG, "configureVHost(nginx) called")

  local vhostpath  = cfg["available_dir"] or cfg["enabled_dir"]
  if opts and opts.prefix then vhostpath = opts.prefix .. vhostpath end -- use prefix (for testing etc.)
  local filename = vhostpath .. "/" .. opts["name"] .. ".conf"
  local tempfile = filename .. ".tmp"
--  tempfile = "/tmp/test.conf"
  local i = 0
  local key
  local cnames = {}     -- canonical ServerName list (required for lclogsplit map entry!)

  -- create temporary config file
  local fh, msg = io.open(tempfile, "w")
  if fh == nil then
    LC.log.print(LC.log.ERR, "Can't open '", tempfile, "' for writing: ", msg)
    return false, "Can't open '" .. tempfile .. "' for writing: " .. msg
  end
  LC.liveconfig.writeHeader(fh)
  fh:write("# Created at: ", os.date("%Y-%m-%d %H:%M:%S %Z"), "\n")
  fh:write("# ----------------------------------------------------------------------------\n\n")

  -- now check every single vhost, configure it if it's for this server:
  local vhostIdx
  local vhostCount = 0

  if type(opts.vhosts) == "table" then
    for vhostIdx=1, #opts.vhosts do
      while opts.vhosts[vhostIdx].server == cfg.type do
        local vhost = opts.vhosts[vhostIdx]

        fh:write("# IP group: '", vhost.ipgroup, "'\n")
        if vhost.ips == nil then
          fh:write("# -> no IPs configured!\n")
          break
        end

        -- found a vHost entry to be configured
        vhostCount = vhostCount + 1

        if opts.suspended then
          -- webspace suspended:
          local dn = { }    -- list with all domain/subdomain names
          for key in pairs(vhost.domains) do
            dn[#dn+1] = key
          end
          write_server(cfg, opts, fh, vhost, dn)
          fh:write("\tlocation /.errorFiles/ {\n")
          fh:write("\t\talias /usr/share/liveconfig/html/;\n")
          fh:write("\t}\n")
          fh:write("\terror_page 503 /.errorFiles/suspended.html;\n")
          fh:write("\treturn 503;\n")
          fh:write("}\n\n")
          break
        end

        -- copy all domain names in a table, and then sort them:
        local sd   = { }    -- list with all domains/subdomains and their destination directory
        local sd_count = 0  -- Lua doesn't support counting table entries with non-integer keys :(
        local r301 = { }    -- list with all domains/subdomains with 301-redirect
        local r301_count = 0
        local r302 = { }    -- list with all domains/subdomains with 302-redirect
        local r302_count = 0
        local prx  = { }    -- list with all domains/subdomains with proxy destination
        local prx_count = 0
        local app  = { }    -- list with all domains/subdomains with web application
        local app_count = 0
        for key in pairs(vhost.domains) do
          local dst = vhost.domains[key].dest

          if vhost.domains[key].type == 1 then
            -- normal (local) (sub)domain
            if dst == nil then dst = '' end
            if sd[dst] == nil then sd[dst] = { } end
            sd[dst][#sd[dst] + 1] = key
            sd_count = sd_count + 1
          end

          if vhost.domains[key].type == 2 then
            -- (sub)domain with 301-redirect
            if r301[dst] == nil then r301[dst] = { } end
            r301[dst][#r301[dst] + 1] = key
            r301_count = r301_count + 1
          end

          if vhost.domains[key].type == 3 then
            -- (sub)domain with 302-redirect
            if r302[dst] == nil then r302[dst] = { } end
            r302[dst][#r302[dst] + 1] = key
            r302_count = r302_count + 1
          end

          if vhost.domains[key].type == 4 then
            -- (sub)domain with proxy destination
            if prx[dst] == nil then prx[dst] = { } end
            prx[dst][#prx[dst] + 1] = key
            prx_count = prx_count + 1
          end

          if vhost.domains[key].type == 5 then
            -- (sub)domain with web application
            if app[dst] == nil then app[dst] = { } end
            app[dst][#app[dst] + 1] = key
            app_count = app_count + 1
          end

        end

        -- create server{} sections for all "normal" (sub)domains
        if sd_count > 0 then
          for key in pairs(sd) do
            write_server(cfg, opts, fh, vhost, sd[key])
            fh:write("\troot\t\t\"", opts.path, "/" .. LC.web.HTDOCS_PATH .. "/", key, "\";\n")

            -- error.log enabled?
            if opts.errorlog then
              fh:write("\terror_log\t", opts.path, "/logs/nginx.error.log warn;\n\n")
            end

            if opts.hasSSI then
              fh:write("\tssi\t\ton;\n\n")
            end

            -- prevent access to .htacces/.htpasswd files
            fh:write("\tlocation ~ /\\.ht {\n")
            fh:write("\t\tdeny all;\n")
            fh:write("\t}\n\n")

            -- CGI not supported...
            fh:write("\tlocation ~ ^/cgi-bin/ {\n")
            fh:write("\t\tdeny all;\n")
            fh:write("\t}\n\n")

            -- PHP settings
            if opts.hasPHP and opts.hasPHP > 0 then
              -- PHP enabled:
              fh:write("\n\t# PHP is enabled\n")
              fh:write("\tindex index.php index.html index.htm;\n")
              fh:write("\tlocation ~ \.php$ {\n")
              fh:write("\t\ttry_files $uri =404;\n")
              fh:write("\t\tinclude /etc/nginx/fastcgi_params;\n")
              fh:write("\t\tfastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;\n")
              fh:write("\t\tfastcgi_index index.php;\n")
              fh:write("\t\tfastcgi_pass unix:", opts.path, "/conf/sockets/nginx-php-fcgi.sock;\n")
              fh:write("\t}\n")
            end

            -- add nice default error pages
            fh:write("\n\tlocation = / {\n")
            fh:write("\t\terror_page\t403 /.errorFiles/coming-soon.html;\n")
            fh:write("\t}\n")
            fh:write("\tlocation /.errorFiles/ {\n")
            fh:write("\t\talias /usr/share/liveconfig/html/;\n")
            fh:write("\t}\n")

            -- password-protected directories:
            if opts.pwprotect then
              fh:write("\n\t# password-protected directories:\n")
              local pwpath
              for pwpath in pairs(opts.pwprotect) do
                local s = "/" .. LC.web.HTDOCS_PATH .. pwpath
                if string.sub(pwpath, 1, string.len(s)) == pwpath then
                  local loc = string.sub(pwpath, string.len(LC.web.HTDOCS_PATH) + 2)
                  if loc == "/" then loc = "" end
                  fh:write("\tlocation ", loc, "/ {\n")
                  fh:write("\t\tauth_basic \"", escape(opts.pwprotect[pwpath].title), "\";\n")
                  fh:write("\t\tauth_basic_user_file ", opts.path, "/conf/.htpasswd;\n")
                  fh:write("\t}\n")
                end
              end
              fh:write("\n")
            end

            -- include custom configuration options
            if LC.fs.is_file(opts.path .. "/conf/nginx.conf") then
              fh:write("    # Include customer-specific configuration options:\n")
              fh:write("    include ", opts.path, "/conf/nginx.conf;\n\n")
            end

            fh:write("}\n\n")
          end
        end

        -- create server{} section for all domains with 301-redirects
        if r301_count > 0 then
          for key in pairs(r301) do
            write_server(cfg, opts, fh, vhost, r301[key])
            fh:write("\trewrite\t\t^/.* \"", key, "\" permanent;\n")
            fh:write("}\n\n")
          end
        end

        -- create server{} section for all domains with 302-redirects
        if r302_count > 0 then
          for key in pairs(r302) do
            write_server(cfg, opts, fh, vhost, r302[key])
            fh:write("\trewrite\t\t^/.* \"", key, "\" redirect;\n")
            fh:write("}\n\n")
          end
        end

        -- create server{} section for all domains with proxy commands
        if prx_count > 0 then
          for key in pairs(prx) do
            write_server(cfg, opts, fh, vhost, prx[key])
            fh:write("\tlocation / {\n")
            fh:write("\t\tproxy_pass\t", key, ";\n")
            fh:write("\t}\n")
            fh:write("}\n\n")
          end
        end

        if app_count > 0 then
          for key in pairs(app) do
            write_server(cfg, opts, fh, vhost, app[key])
            fh:write("\troot\t\t\"", opts.path, "/apps/", key, "\";\n")

            if opts.hasSSI then
              fh:write("\tssi\t\ton;\n\n")
            end

            -- prevent access to .htacces/.htpasswd files
            fh:write("\tlocation ~ /\\.ht {\n")
            fh:write("\t\tdeny all;\n")
            fh:write("\t}\n\n")

            -- CGI not supported...
            fh:write("\tlocation ~ ^/cgi-bin/ {\n")
            fh:write("\t\tdeny all;\n")
            fh:write("\t}\n\n")

            -- PHP settings
            if opts.hasPHP and opts.hasPHP > 0 then
              -- PHP enabled:
              fh:write("\n\t# PHP is enabled\n")
              fh:write("\tindex index.php index.html index.htm;\n")
              fh:write("\tlocation ~ \.php$ {\n")
              fh:write("\t\ttry_files $uri =404;\n")
              fh:write("\t\tinclude /etc/nginx/fastcgi_params;\n")
              fh:write("\t\tfastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;\n")
              fh:write("\t\tfastcgi_index index.php;\n")
              fh:write("\t\tfastcgi_pass unix:", opts.path, "/conf/sockets/nginx-php-fcgi.sock;\n")
              fh:write("\t}\n")
            end

            -- add nice default error pages
            fh:write("\n\tlocation = / {\n")
            fh:write("\t\terror_page\t403 /.errorFiles/coming-soon.html;\n")
            fh:write("\t}\n")
            fh:write("\tlocation /.errorFiles/ {\n")
            fh:write("\t\talias /usr/share/liveconfig/html/;\n")
            fh:write("\t}\n")

            -- include custom configuration options
            if LC.fs.is_file(opts.path .. "/conf/nginx.conf") then
              fh:write("    # Include customer-specific configuration options:\n")
              fh:write("    include ", opts.path, "/conf/nginx.conf;\n\n")
            end

            fh:write("}\n\n")
          end
        end

        break -- while(true)
      end
    end -- for...
  end -- if type(opts.vhosts) == "table"

  if vhostCount == 0 then
    fh:write("# No IPs/Domains configured for this vHost.\n")
  else
    if opts.hasPHP and opts.hasPHP > 0 then
      fh:write("# PHP-FCGI configuration - DO NOT MODIFY!\n")
      fh:write("# NGINX_FCGI_USER=", opts.name, "\n")
      fh:write("# NGINX_FCGI_SOCKET=", opts.path, "/conf/sockets/nginx-php-fcgi.sock\n")
      fh:write("# NGINX_FCGI_CHILDREN=5\n")
      fh:write("# NGINX_FCGI_MAX_REQUESTS=1000\n")
      if LC.fs.is_file(opts.path .. "/.php5/php.ini") then
        fh:write("# NGINX_FCGI_INI_PATH=", opts.path, "/.php5\n")
      else
        fh:write("# NGINX_FCGI_INI_PATH=", opts.path, "/conf/php5\n")
      end
      fh:write("\n")

      if not LC.fs.is_dir(opts.path .. "/conf/sockets") then
        LC.fs.mkdir(opts.path .. "/conf/sockets")
        LC.fs.setperm(opts.path .. "/conf/sockets", 755, opts.user, opts.group)
      end
    end

  end

  -- close (temporary) config file
  LC.liveconfig.writeFooter(fh)
  fh:close()

  -- rename config file (atomic)
  LC.fs.rename(tempfile, filename)

  -- update map file (for lclogsplit)
  updateMapFile(cfg, opts, cnames, opts.path .. "/logs/access.log")

  if vhostCount == 0 then
    -- disable configuration, remove config file
    if cfg["disable_cmd"] ~= nil then
      os.execute(cfg["disable_cmd"] .. " " .. opts["name"] .. ".conf")
    elseif cfg["enabled_dir"] ~= nil and vhostpath ~= cfg["enabled_dir"] and LC.fs.is_file(cfg["enabled_dir"] .. "/" .. opts["name"] .. ".conf") then
      -- remove link manually:
      os.remove(cfg["enabled_dir"] .. "/" .. opts["name"] .. ".conf")
    end
    os.remove(filename)

    -- stop PHP-FCGI for this customer
    if LC.fs.is_file("/etc/init.d/nginx-php-fcgi") then
      os.execute("/etc/init.d/nginx-php-fcgi stop " .. opts.name)
    end
  else
    -- if not done yet, enable config
    if cfg["enable_cmd"] ~= nil then
      os.execute(cfg["enable_cmd"] .. " " .. opts["name"] .. ".conf")
    elseif cfg["enabled_dir"] ~= nil and vhostpath ~= cfg["enabled_dir"] and not LC.fs.is_file(cfg["enabled_dir"] .. "/" .. opts["name"] .. ".conf") then
      -- link manually:
      os.execute("ln -s " .. vhostpath .. "/" .. opts["name"] .. ".conf " .. cfg["enabled_dir"] .. "/" .. opts["name"] .. ".conf")
    end

    -- (re)start PHP-FCGI for this customer
    if LC.fs.is_file("/etc/init.d/nginx-php-fcgi") then
      os.execute("/etc/init.d/nginx-php-fcgi restart " .. opts.name)
    end
  end

  -- reload web server configuration
  LC.timeout.set('nginx.reload', 10, 60)

  return true

end

-- ---------------------------------------------------------------------------
-- reload()
--
-- Reload NGINX configuration
-- ---------------------------------------------------------------------------
function reload()
  LC.log.print(LC.log.DEBUG, "nginx.reload() called")
  -- get configuration
  local cfg = LC.web.getConfig('nginx')
  if cfg == nil then
    LC.log.print(LC.log.ERR, "nginx.reload(): no configuration for 'nginx' available!?")
    return
  end
  -- get reload command
  if cfg.reload_cmd == nil then
    LC.log.print(LC.log.ERR, "nginx.reload(): no reload command for 'nginx' available!?")
    return
  end

  -- reload service
  os.execute(cfg.reload_cmd)

end

-- ---------------------------------------------------------------------------
-- deleteAccount()
--
-- Delete account/vHost
-- ---------------------------------------------------------------------------
function deleteAccount(cfg, name)
  local vhostpath  = cfg["available_dir"] or cfg["enabled_dir"]
  local filename = vhostpath .. "/" .. name .. ".conf"

  if not LC.fs.is_file(filename) then return end

  if cfg["disable_cmd"] ~= nil then
    os.execute(cfg["disable_cmd"] .. " " .. name .. ".conf")
  end
  os.remove(filename)

  -- reload web server configuration
  LC.timeout.set('nginx.reload', 10, 60)

end

-- <EOF>----------------------------------------------------------------------
