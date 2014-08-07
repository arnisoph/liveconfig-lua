--  _    _          ___           __ _     (R)
-- | |  (_)_ _____ / __|___ _ _  / _(_)__ _
-- | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
-- |____|_|\_/\___|\___\___/_||_|_| |_\__, |
--                                    |___/
-- Copyright (c) 2009-2012 Keppler IT GmbH.
-- ---------------------------------------------------------------------------
-- common/lua/popimap.lua
-- POP/IMAP server management
-- $Id: popimap.lua 2400 2013-06-12 14:28:41Z kk $
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
module("popimap")

-- Exported functions
-- load()
-- detect()
-- getConfig()
-- install()
-- uninstall()
-- configure()
-- addMailbox()
-- editMailbox()
-- deleteMailbox()

-- Exported variables
-- -none-

-- ---------------------------------------------------------------------------

-- module variables
local modlist = { }

-- ---------------------------------------------------------------------------
-- load(modname)
--
-- Load "driver" module for a specific pop/imap server
-- ---------------------------------------------------------------------------
function load(mod)
  modlist[mod] = require(mod)
end

-- ---------------------------------------------------------------------------
-- detect()
--
-- Detect installed pop/imap server packages
-- ---------------------------------------------------------------------------
function detect()
  local data = {}
  local mod

  -- check if pop/imap server software was already detected; avoid double-detection
  -- also across multiple threads
  LC.mutex.lock("popimap.detect")

  if LCS.popimap ~= nil then
    if LCS.popimap.data ~= nil then
      -- pop/imap server software already detected; load values from global LCS storage
      LC.mutex.unlock("popimap.detect")
      return LCS.popimap.data
    end
  end

  -- run detection handler for all installed driver modules
  LC.log.print(LC.log.DEBUG, "running popimap.detect()");
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

  LCS.popimap = {
    generated = true,
    data      = data    -- LCS.popimap.data = (local)data
  }

  LC.mutex.unlock("popimap.detect")
  
  return data
end

-- ---------------------------------------------------------------------------
-- getConfig()
--
-- Return configuration table for specified pop/imap server
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
-- Start management of pop/imap server
-- ---------------------------------------------------------------------------
function install(config, opts)
  local res, msg
  if config == nil or config.type == nil then
    return false, "popimap.install(): no configuration submitted"
  end
  if modlist[config.type] == nil then
    LC.log.print(LC.log.ERR, "No module for pop/imap server '", config.type, "' found")
    return false, "No module for pop/imap server '" .. config.type .. "' found"
  end
  -- run install() function from pop/imap server module
  res, msg = modlist[config.type].install(config, opts)

  if not res then
    return false, msg
  end

  -- restart pop/imap server
  if config.restart_cmd ~= nil then
    local rc = os.execute(config.restart_cmd)
    if rc ~= 0 then
      return false, "Error while reloading configuration (exit code: " .. rc .. ")"
    end
  end

  return true
end

-- ---------------------------------------------------------------------------
-- uninstall()
--
-- Stop management of pop/imap server
-- ---------------------------------------------------------------------------
function uninstall(config, opts)
  if config == nil or config.type == nil then
    return false
  end
  if modlist[config.type] == nil then
    LC.log.print(LC.log.ERR, "No module for pop/imap server '", config.type, "' found")
    return false
  end

  -- run uninstall() function from POP3/IMAP server module
  return modlist[config.type].uninstall(config, opts)
end

-- ---------------------------------------------------------------------------
-- configure()
--
-- Configure pop/imap server
-- ---------------------------------------------------------------------------
function configure(opts)

  LC.log.print(LC.log.DEBUG, "LC.popimap.configure()")

  local res, msg
  -- check options
  if opts == nil or opts.server == nil then
    return false, "No pop/imap server specified"
  end

  -- get configuration
  local cfg = getConfig(opts.server)
  if cfg == nil then
    return false, "pop/imap server '" .. opts.server .. "' not found"
  end

  local statusfile = cfg["statusfile"]
  if opts and opts.prefix then
    statusfile = opts.prefix .. statusfile
  end

  -- core configuration (LiveConfig) already installed?
  if not LC.fs.is_file(statusfile) then
    -- install LiveConfig configuration
    res, msg = modlist[cfg.type].install(cfg, opts)
  else
    -- update core configuration
    res, msg = modlist[cfg.type].configure(cfg, opts)
  end

  if not res then
    return false, msg
  end

  -- restart pop/imap server
  if cfg.restart_cmd ~= nil then
    local rc = os.execute(cfg.restart_cmd)
    if rc ~= 0 then
      return false, "Error while reloading configuration (exit code: " .. rc .. ")"
    end
  end

  return true
end

-- ---------------------------------------------------------------------------
-- addMailbox()
--
-- Add mailboxes into popimap server config file
-- ---------------------------------------------------------------------------
function addMailbox(opts, data)
  LC.log.print(LC.log.DEBUG, "LC.popimap.addMailbox()")

  -- get configuration
  local cfg = getConfig(data.server)
  if cfg == nil then
    LC.log.print(LC.log.ERR, "POP/IMAP server '", data.server, "' not found")
    return false, "POP/IMAP server '" .. data.server .. "' not found"
  end

  if modlist[cfg.type] == nil then
    LC.log.print(LC.log.ERR, "No module for pop/imap server '", cfg.type, "' found")
    return false, "No module for pop/imap server '" .. cfg.type .. "' found"
  end

  -- run addMailbox() function from popimap server module
  LC.mutex.lock("popimap.configure")
  local ret = modlist[cfg.type].addMailbox(cfg, opts, data)
  LC.mutex.unlock("popimap.configure")

  return ret
end

-- ---------------------------------------------------------------------------
-- editMailbox()
--
-- Edit mailbox configuration
-- ---------------------------------------------------------------------------
function editMailbox(opts, data)
  LC.log.print(LC.log.DEBUG, "LC.popimap.editMailbox()")

  -- get configuration
  local cfg = getConfig(data.server)
  if cfg == nil then
    LC.log.print(LC.log.ERR, "POP/IMAP server '", data.server, "' not found")
    return false, "POP/IMAP server '" .. data.server .. "' not found"
  end

  if modlist[cfg.type] == nil then
    LC.log.print(LC.log.ERR, "No module for pop/imap server '", cfg.type, "' found")
    return false, "No module for pop/imap server '" .. cfg.type .. "' found"
  end

  -- run editMailbox() function from popimap server module
  LC.mutex.lock("popimap.configure")
  local ret = modlist[cfg.type].editMailbox(cfg, opts, data)
  LC.mutex.unlock("popimap.configure")

  return ret
end

-- ---------------------------------------------------------------------------
-- deleteMailbox()
--
-- Delete mailbox
-- ---------------------------------------------------------------------------
function deleteMailbox(opts, data)
  LC.log.print(LC.log.DEBUG, "LC.popimap.deleteMailbox()")

  -- get configuration
  local cfg = getConfig(data.server)
  if cfg == nil then
    LC.log.print(LC.log.ERR, "POP/IMAP server '", data.server, "' not found")
    return false, "POP/IMAP server '" .. data.server .. "' not found"
  end

  if modlist[cfg.type] == nil then
    LC.log.print(LC.log.ERR, "No module for pop/imap server '", cfg.type, "' found")
    return false, "No module for pop/imap server '" .. cfg.type .. "' found"
  end

  -- run deleteMailbox() function from popimap server module
  LC.mutex.lock("popimap.configure")
  local ret = modlist[cfg.type].deleteMailbox(cfg, opts, data)
  LC.mutex.unlock("popimap.configure")

  return ret
end

-- <EOF>----------------------------------------------------------------------
