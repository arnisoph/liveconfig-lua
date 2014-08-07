--  _    _          ___           __ _     (R)
-- | |  (_)_ _____ / __|___ _ _  / _(_)__ _
-- | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
-- |____|_|\_/\___|\___\___/_||_|_| |_\__, |
--                                    |___/
-- Copyright (c) 2009-2012 Keppler IT GmbH.
-- ---------------------------------------------------------------------------
-- common/lua/db.lua
-- DB server management
-- $Id: db.lua 2169 2013-03-11 14:21:47Z kk $
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
module("db")

-- Exported functions
-- load()
-- detect()
-- getConfig()
-- install()
-- uninstall()
-- configure()

-- Exported variables
-- -none-

-- ---------------------------------------------------------------------------

-- module variables
local modlist = { }

-- ---------------------------------------------------------------------------
-- load(modname)
--
-- Load "driver" module for a specific DB server
-- ---------------------------------------------------------------------------
function load(mod)
  modlist[mod] = require(mod)
end

-- ---------------------------------------------------------------------------
-- detect()
--
-- Detect installed DB server packages
-- ---------------------------------------------------------------------------
function detect()
  local data = {}
  local mod

  -- check if DB server software was already detected; avoid double-detection
  -- also across multiple threads
  LC.mutex.lock("db.detect")

  if LCS.db ~= nil then
    if LCS.db.data ~= nil then
      -- DB server software already detected; load values from global LCS storage
      LC.mutex.unlock("db.detect")
      return LCS.db.data
    end
  end

  -- run detection handler for all installed driver modules
  LC.log.print(LC.log.DEBUG, "running db.detect()");
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

  LCS.db = {
    generated = true,
    data      = data    -- LCS.db.data = (local)data
  }

  LC.mutex.unlock("db.detect")
  
  return data
end

-- ---------------------------------------------------------------------------
-- getConfig()
--
-- Return configuration table for specified DB server
-- (eg. "postfix")
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
-- Start management of DB server
-- ---------------------------------------------------------------------------
function install(config, opts)
  if config == nil or config.type == nil then
    return false, "DB.install(): no configuration submitted"
  end
  if modlist[config.type] == nil then
    LC.log.print(LC.log.ERR, "No module for DB server '", config.type, "' found")
    return false, "No module for DB server '" .. config.type .. "' found"
  end
  -- run install() function from DB server module
  return modlist[config.type].install(config, opts)
end

-- ---------------------------------------------------------------------------
-- uninstall()
--
-- Stop management of DB server
-- ---------------------------------------------------------------------------
function uninstall(config, opts)
  if config == nil or config.type == nil then
    return false
  end
  if modlist[config.type] == nil then
    LC.log.print(LC.log.ERR, "No module for DB server '", config.type, "' found")
    return false
  end
  if not modlist[config.type].uninstall(config, opts) then
    return false
  end
end

-- ---------------------------------------------------------------------------
-- configure()
--
-- Configure DB server
-- ---------------------------------------------------------------------------
function configure(opts)

  LC.log.print(LC.log.DEBUG, "LC.db.configure()")

  local res, msg
  -- check options
  if opts == nil or opts.server == nil then
    return false, "No DB server specified"
  end

  -- get configuration
  local cfg = getConfig(opts.server)
  if cfg == nil then
    return false, "DB server '" .. opts.server .. "' not found"
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
  end

  -- update core configuration
  res, msg = modlist[cfg.type].configure(cfg, opts)
  if not res then
    return false, msg
  end

  -- restart DB server
  LC.log.print(LC.log.DEBUG, "Restart cmd: ", cfg.restart_cmd)
  if cfg.restart_cmd ~= nil then
    local rc = os.execute(cfg.restart_cmd)
    LC.log.print(LC.log.DEBUG, "Return value: ", rc)
    if rc ~= 0 then
      return false, "Error while reloading configuration (exit code: " .. rc .. ")"
    end
  end

  return true
end

-- <EOF>----------------------------------------------------------------------
