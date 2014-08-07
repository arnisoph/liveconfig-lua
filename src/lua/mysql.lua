--  _    _          ___           __ _     (R)
-- | |  (_)_ _____ / __|___ _ _  / _(_)__ _
-- | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
-- |____|_|\_/\___|\___\___/_||_|_| |_\__, |
--                                    |___/
-- Copyright (c) 2009-2013 Keppler IT GmbH.
-- ---------------------------------------------------------------------------
-- common/lua/mysql.lua
-- Lua module to manage MySQL database server
-- $Id: mysql.lua 2506 2013-07-29 14:04:59Z kk $
-- ---------------------------------------------------------------------------
-- This is the "driver" module for mysql db server.
-- It must be loaded by the command
--   LC.db.load("mysql")
-- Usually, this should happen at liveconfig.lua (or, if you have a customized
-- module, at custom.lua)
-- ---------------------------------------------------------------------------

-- Imported functions
local LC = LC
local LCS = LCS -- import liveconfig global storage
local type = type
local io = io
local os = os
local string = string

-- Module declaration
module("mysql")

-- Exported functions
--   detect()
--   install()
--   uninstall()
--   configure()

-- ---------------------------------------------------------------------------
-- getBinaryVersion()
--
-- Return the binary version number from mysql
-- ---------------------------------------------------------------------------
local function getBinaryVersion(bin)
  local handle = io.popen(bin .. " -V", "r")
  local ret = handle:read("*a")
  handle:close()
  local v = string.match(ret, "Distrib (%d+%.%d+[%.%d+]*)")
  return v
end

-- ---------------------------------------------------------------------------
-- detect()
--
-- Detect if an mysql db server is installed. If yes, return a table containing
-- all relevant informations:
--   type          => "mysql"
--   binname       => file name of the mysql binary (eg. "/usr/sbin/mysqld")
--   binversion    => binary version (eg. "2.5.5")
--   pkgname       => name of the package (see below)
--   pkgversion    => package version number (eg. "2.2.3-4+etch11")
--   configpath    => Main configuration path for mysql
--   configfile    => LiveConfigs' configuration file (snippet)
--   statusfile    => LiveConfigs' status file (containing config version etc.)
--   defaultlog    => Default log file (for default and unknown/unconfigured vhosts)
--   start_cmd     => command to start mysql
--   stop_cmd      => command to stop mysql
--   reload_cmd    => command to re-load configuration
--   restart_cmd   => command to re-start mysql process
--
-- If pkgversion is 'nil', then mysql Server was most propably not installed
-- as native distribution package, but compiled/installed manually.
-- ---------------------------------------------------------------------------
function detect()

  local pkg, v, bin

-- first check for distribution-specific packages
  if LC.distribution.family == "Debian" or LC.distribution.family == "RedHat" or LC.distribution.family == "BSD" then
    pkg, v = LC.distribution.hasPackage(
      'mysql-server', 'mysql-server-5.0', 'mysql-server-5.1', 'mysql-server-5.5', 'mysql-server-5.6',
      'percona-server-server', 'percona-server-server-5.1', 'percona-server-server-5.5',
      'mariadb-server', 'mariadb-server-5.5', 'mariadb-galera-server')
  elseif LC.distribution.family == "SUSE" then
    pkg, v = LC.distribution.hasPackage('mysql-community-server', 'mariadb', 'mysql')
  else
    pkg, v = LC.distribution.hasPackage('mysql', 'MariaDB', 'MariaDB-Galera')
  end
  if pkg ~= nil then
    LC.log.print(LC.log.DEBUG, "Found package '", pkg, "' (Version ", v, ")")
    if LC.distribution.family == "BSD" then
      bin = "/usr/local/bin/mysql"
    else
      bin = "/usr/bin/mysql"
    end
    -- get binary version
    local bv = getBinaryVersion(bin)
    if bv ~= nil then
      -- ok, we have all informations. return data table:
      if LC.distribution.family == "RedHat" then
        local data = {
          ["type"]          = "mysql",
          ["binname"]       = bin,
          ["binversion"]    = bv,
          ["pkgname"]       = pkg,
          ["pkgversion"]    = v,
          ["configpath"]    = "/etc/mysql",
          ["configfile"]    = "/etc/my.cnf",
          ["statusfile"]    = "/etc/mysql/liveconfig.status",
          ["defaultlog"]    = "/var/log/mysql.log",
          ["start_cmd"]     = "/sbin/service mysql start",
          ["stop_cmd"]      = "/sbin/service mysql stop",
          ["reload_cmd"]    = "/sbin/service mysql reload",
          ["restart_cmd"]   = "/sbin/service mysql restart",
        }
        return data
      elseif LC.distribution.family == "BSD" then
        local data = {
          ["type"]          = "mysql",
          ["binname"]       = bin,
          ["binversion"]    = bv,
          ["pkgname"]       = pkg,
          ["pkgversion"]    = v,
          ["configpath"]    = "/var/db/mysql",
          ["configfile"]    = "/usr/local/etc/my.cnf",
          ["statusfile"]    = "/etc/mysql/liveconfig.status",
          ["defaultlog"]    = "/var/log/mysql.log",
          ["start_cmd"]     = "/usr/local/etc/rc.d/mysql-server onestart",
          ["stop_cmd"]      = "/usr/local/etc/rc.d/mysql-server onestop",
          ["reload_cmd"]    = "",
          ["restart_cmd"]   = "/usr/local/etc/rc.d/mysql-server onerestart",
        }
        return data
      else
        local data = {
          ["type"]          = "mysql",
          ["binname"]       = bin,
          ["binversion"]    = bv,
          ["pkgname"]       = pkg,
          ["pkgversion"]    = v,
          ["configpath"]    = "/etc/mysql",
          ["configfile"]    = "/etc/mysql/my.cnf",
          ["statusfile"]    = "/etc/mysql/liveconfig.status",
          ["defaultlog"]    = "/var/log/mysql.log",
          ["start_cmd"]     = "/etc/init.d/mysql start",
          ["stop_cmd"]      = "/etc/init.d/mysql stop",
          ["reload_cmd"]    = "/etc/init.d/mysql reload",
          ["restart_cmd"]   = "/etc/init.d/mysql restart",
        }
        return data
      end
    end
    -- else: fall trough, to check for custom mysql installation
    LC.log.print(LC.log.DEBUG, "LC.mysql.detect(): Found Mysql package '", pkg, "', but no binary at ", bin)
  end
end

-- ---------------------------------------------------------------------------
-- install(cfg, opts)
--
-- Install LiveConfig configuration files for mysql Server
-- ---------------------------------------------------------------------------
function install(cfg, opts)
  LC.log.print(LC.log.INFO, "Activating management of mysql Server")

  local fh, status, msg
  local configpath = cfg["configpath"]
  local configfile = cfg["configfile"]
  local statusfile = cfg["statusfile"]

  if opts and opts.prefix then
    -- use prefix (for testing etc.)
    configpath = opts.prefix .. configpath
    configfile = opts.prefix .. configfile
    statusfile = opts.prefix .. statusfile
  end

  -- back up old default main.cf file (if existing)
  if LC.fs.is_file( configfile) and not LC.fs.is_file( configfile .. ".lcbak") then
    LC.fs.rename( configfile,  configfile .. ".lcbak")
  end

  -- write default config file main.cf:
  configure(cfg, opts)

  -- vemutlich überflüssig, da in configure revision gesetzt wird
  -- write status file
  -- LC.liveconfig.writeStatus(statusfile, cfg.type, 0, '0000-00-00 00:00:00')

  return true
end

-- ---------------------------------------------------------------------------
-- uninstall(cfg, opts)
--
-- Remove LiveConfig configuration files from mysql Server
-- ---------------------------------------------------------------------------
function uninstall(cfg, opts)
  LC.log.print(LC.log.INFO, "Disabling management of MySQL server")

  local status, msg
  local statusfile = cfg["statusfile"]

  if opts and opts.prefix then
    -- use prefix (for testing etc.)
    statusfile = opts.prefix .. statusfile
  end

  -- remove status file
  status, msg = os.remove(statusfile)
  if status == nil then
    LC.log.print(LC.log.ERR, "Deletion of '", statusfile, "' failed: ", msg)
  end

  return true
end


-- ---------------------------------------------------------------------------
-- configure(cfg, opts)
--
-- Configure mysql Server
-- ---------------------------------------------------------------------------
function configure(cfg, opts)

  local fh, status, msg
  local statusfile = cfg["statusfile"]

  if opts and opts.prefix then
    -- use prefix (for testing etc.)
    statusfile = opts.prefix .. statusfile
  end

  -- update status file
  LC.liveconfig.writeStatus(statusfile, cfg.type, opts.revision, '0000-00-00 00:00:00')

  return true
end


-- <EOF>----------------------------------------------------------------------
