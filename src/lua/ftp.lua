--  _    _          ___           __ _     (R)
-- | |  (_)_ _____ / __|___ _ _  / _(_)__ _
-- | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
-- |____|_|\_/\___|\___\___/_||_|_| |_\__, |
--                                    |___/
-- Copyright (c) 2009-2012 Keppler IT GmbH.
-- ---------------------------------------------------------------------------
-- common/lua/ftp.lua
-- FTP server management
-- $Id: ftp.lua 2312 2013-05-07 16:53:30Z kk $
-- ---------------------------------------------------------------------------

-- Imported functions
local LC = LC
local LCS = LCS
local type = type
local io = io
local os = os
local string = string
local require = require
local pairs = pairs

-- Module declaration
module("ftp")

-- Exported functions
-- load()
-- detect()
-- getConfig()
-- install()
-- uninstall()
-- configure()
-- add()
-- del()
-- lock()
-- unlock()

-- Exported variables
-- -none-

-- ---------------------------------------------------------------------------

-- module variables
local modlist = { }

-- ---------------------------------------------------------------------------
-- load(modname)
--
-- Load "driver" module for a specific FTP server
-- ---------------------------------------------------------------------------
function load(mod)
  modlist[mod] = require(mod)
end

-- ---------------------------------------------------------------------------
-- detect()
--
-- Detect installed FTP server packages
-- ---------------------------------------------------------------------------
function detect()
  local data = {}
  local mod

  -- check if FTP server software was already detected; avoid double-detection
  -- also across multiple threads
  LC.mutex.lock("ftp.detect")

  if LCS.ftp ~= nil then
    if LCS.ftp.data ~= nil then
      -- FTP server software already detected; load values from global LCS storage
      LC.mutex.unlock("ftp.detect")
      return LCS.ftp.data
    end
  end

  -- run detection handler for all installed driver modules
  LC.log.print(LC.log.DEBUG, "running ftp.detect()");
  for mod in pairs(modlist) do
    local m = modlist[mod].detect()
    if m then
      data[#data+1] = m
      -- now check for configuration revision (if already managed by LiveConfig)
      if m.statusfile and LC.fs.is_file(m.statusfile) then
        local r = LC.liveconfig.readStatus(m.statusfile)
        if r and r.revision then
          -- this module is in use
          data[#data].revision = r.revision
          -- call init function (if existing)
          if modlist[mod].init then
            modlist[mod].init()
          end
        end
      end
    end
  end

  LCS.ftp = {
    generated = true,
    data      = data    -- LCS.ftp.data = (local)data
  }

  LC.mutex.unlock("ftp.detect")

  return data
end

-- ---------------------------------------------------------------------------
-- getConfig()
--
-- Return configuration table for specified FTP server
-- (eg. "proftpd")
-- ---------------------------------------------------------------------------
function getConfig(name)
  local w = detect()
  local i = 1;
  while w[i] do
    if w[i]['type'] == name then
      return w[i]
    end
    i=i+1
  end
end

-- ---------------------------------------------------------------------------
-- install()
--
-- Start management of FTP server
-- ---------------------------------------------------------------------------
function install(config, opts)
  local ret, msg
  if config == nil or config.type == nil then
    return false, "FTP.install(): no configuration submitted"
  end
  if modlist[config.type] == nil then
    LC.log.print(LC.log.ERR, "No module for FTP server '", config.type, "' found")
    return false, "No module for FTP server '" .. config.type .. "' found"
  end

  -- run install() function from FTP server module
  ret, msg = modlist[config.type].install(config, opts)
  if ret ~= true then
    return ret, msg
  end

  -- call init function (if existing)
  if modlist[config.type].init then
    modlist[config.type].init()
  end

  return ret
end

-- ---------------------------------------------------------------------------
-- uninstall()
--
-- Stop management of FTP server
-- ---------------------------------------------------------------------------
function uninstall(config, opts)
  if config == nil or config.type == nil then
    return false
  end
  if modlist[config.type] == nil then
    LC.log.print(LC.log.ERR, "No module for FTP server '", config.type, "' found")
    return false
  end

  -- run uninstall() function from FTP server module
  return modlist[config.type].uninstall(config, opts)
end

-- ---------------------------------------------------------------------------
-- configure()
--
-- Configure FTP server
-- ---------------------------------------------------------------------------
function configure(opts)

  LC.log.print(LC.log.DEBUG, "LC.ftp.configure()")

  local res, msg
  -- check options
  if opts == nil or opts.server == nil then
    return false, "No FTP server specified"
  end

  -- get configuration
  local cfg = getConfig(opts.server)
  if cfg == nil then
    return false, "FTP server '" .. opts.server .. "' not found"
  end

  local statusfile = cfg["statusfile"]
  if opts and opts.prefix then
    statusfile = opts.prefix .. statusfile
  end

  -- core configuration (LiveConfig) already installed?
  if not LC.fs.is_file(statusfile) then
    -- install LiveConfig configuration
    res, msg = modlist[cfg.type].install(cfg, opts)
    if res == false then
      return false, msg
    end
    -- call init function (if existing)
    if modlist[cfg.type].init then
      modlist[cfg.type].init()
    end
  end

  -- update configuration
  res, msg = modlist[cfg.type].configure(cfg, opts)
  if not res then
    return false, msg
  end

  -- restart FTP server
  if cfg.restart_cmd ~= nil then
    local rc = os.execute(cfg.restart_cmd)
    if rc ~= 0 then
      return false, "Error while reloading configuration (exit code: " .. rc .. ")"
    end
  end

  -- now check for configuration revision
  if cfg.statusfile and LC.fs.is_file(cfg.statusfile) then
    local r = LC.liveconfig.readStatus(cfg.statusfile)
    if r and r.revision then
      cfg.revision = r.revision
    end
  end

  return true
end

-- ---------------------------------------------------------------------------
-- add()
--
-- Add virtual FTP account
-- ---------------------------------------------------------------------------
function add(opts)

  -- find managed FTP server, and add account
  local cfg = LC.ftp.detect()
  local key, value
  for key, value in pairs(cfg) do
    if value.revision ~= nil then
      LC.mutex.lock("ftp.configure")
      local ret = modlist[value.type].add(value, opts)
      LC.mutex.unlock("ftp.configure")
      return ret
    end
  end

  -- no managed FTP server found
  LC.log.print(LC.log.ERR, "No managed FTP server found")
  return false

end

-- ---------------------------------------------------------------------------
-- del()
--
-- Delete virtual FTP account
-- ---------------------------------------------------------------------------
function del(opts)

  -- find managed FTP server, and delete account
  local cfg = LC.ftp.detect()
  local key, value
  for key, value in pairs(cfg) do
    if value.revision ~= nil then
      LC.mutex.lock("ftp.configure")
      local ret = modlist[value.type].del(value, opts)
      LC.mutex.unlock("ftp.configure")
      return ret
    end
  end

  -- no managed FTP server found
  LC.log.print(LC.log.ERR, "No managed FTP server found")
  return false

end

-- ---------------------------------------------------------------------------
-- update()
--
-- Update password for virtual FTP account
-- ---------------------------------------------------------------------------
function update(opts)

  -- same as add():
  return add(opts)

end

-- ---------------------------------------------------------------------------
-- lock()
--
-- Lock virtual FTP accounts
-- ---------------------------------------------------------------------------
function lock(users)

  -- find managed FTP server, and lock accounts
  local cfg = LC.ftp.detect()
  local key, value
  for key, value in pairs(cfg) do
    if value.revision ~= nil then
      LC.mutex.lock("ftp.configure")
      local ret = modlist[value.type].lock(value, users)
      LC.mutex.unlock("ftp.configure")
      return ret
    end
  end

  -- no managed FTP server found
  LC.log.print(LC.log.ERR, "No managed FTP server found")
  return false

end

-- ---------------------------------------------------------------------------
-- unlock()
--
-- Unlock virtual FTP accounts
-- ---------------------------------------------------------------------------
function unlock(users)

  -- find managed FTP server, and unlock accounts
  local cfg = LC.ftp.detect()
  local key, value
  for key, value in pairs(cfg) do
    if value.revision ~= nil then
      LC.mutex.lock("ftp.configure")
      local ret = modlist[value.type].unlock(value, users)
      LC.mutex.unlock("ftp.configure")
      return ret
    end
  end

  -- no managed FTP server found
  LC.log.print(LC.log.ERR, "No managed FTP server found")
  return false

end


-- <EOF>----------------------------------------------------------------------
