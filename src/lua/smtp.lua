--  _    _          ___           __ _     (R)
-- | |  (_)_ _____ / __|___ _ _  / _(_)__ _
-- | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
-- |____|_|\_/\___|\___\___/_||_|_| |_\__, |
--                                    |___/
-- Copyright (c) 2009-2012 Keppler IT GmbH.
-- ---------------------------------------------------------------------------
-- common/lua/smtp.lua
-- SMTP server management
-- $Id: smtp.lua 2806 2014-03-25 13:25:19Z kk $
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
module("smtp")

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
-- Load "driver" module for a specific smtp server
-- ---------------------------------------------------------------------------
function load(mod)
  modlist[mod] = require(mod)
end

-- ---------------------------------------------------------------------------
-- detect()
--
-- Detect installed smtp server packages
-- ---------------------------------------------------------------------------
function detect()
  local data = {}
  local mod

  -- check if smtp server software was already detected; avoid double-detection
  -- also across multiple threads
  LC.mutex.lock("smtp.detect")

  if LCS.smtp ~= nil then
    if LCS.smtp.data ~= nil then
      -- smtp server software already detected; load values from global LCS storage
      LC.mutex.unlock("smtp.detect")
      return LCS.smtp.data
    end
  end

  -- run detection handler for all installed driver modules
  LC.log.print(LC.log.DEBUG, "running smtp.detect()");
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
            modlist[mod].init(m)
          end
        end
      end
    end
  end

  LCS.smtp = {
    generated = true,
    data      = data    -- LCS.smtp.data = (local)data
  }

  LC.mutex.unlock("smtp.detect")
  
  return data
end

-- ---------------------------------------------------------------------------
-- getConfig()
--
-- Return configuration table for specified smtp server
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
-- Start management of smtp server
-- ---------------------------------------------------------------------------
function install(config, opts)
  local res, msg
  if config == nil or config.type == nil then
    return false, "smtp.install(): no configuration submitted"
  end
  if modlist[config.type] == nil then
    LC.log.print(LC.log.ERR, "No module for smtp server '", config.type, "' found")
    return false, "No module for smtp server '" .. config.type .. "' found"
  end

  LC.mutex.lock("smtp.configure")

  -- run install() function from smtp server module
  res, msg = modlist[config.type].install(config, opts)

  if not res then
    LC.mutex.unlock("smtp.configure")
    return false, msg
  end

  -- restart smtp server
  if config.restart_cmd ~= nil then
    local rc = os.execute(config.restart_cmd)
    if rc ~= 0 then
      LC.mutex.unlock("smtp.configure")
      return false, "Error while reloading configuration (exit code: " .. rc .. ")"
    end
  end

  LC.mutex.unlock("smtp.configure")

end

-- ---------------------------------------------------------------------------
-- uninstall()
--
-- Stop management of smtp server
-- ---------------------------------------------------------------------------
function uninstall(config, opts)
  if config == nil or config.type == nil then
    return false
  end
  if modlist[config.type] == nil then
    LC.log.print(LC.log.ERR, "No module for smtp server '", config.type, "' found")
    return false
  end

  -- run uninstall() function from mail server module
  return modlist[config.type].uninstall(config, opts)
end

-- ---------------------------------------------------------------------------
-- configure()
--
-- Configure smtp server
-- ---------------------------------------------------------------------------
function configure(opts)

  LC.log.print(LC.log.DEBUG, "LC.smtp.configure()")

  local res, msg
  -- check options
  if opts == nil or opts.server == nil then
    return false, "No smtp server specified"
  end

  -- get configuration
  local cfg = getConfig(opts.server)
  if cfg == nil then
    return false, "SMTP server '" .. opts.server .. "' not found"
  end

  LC.mutex.lock("smtp.configure")

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
    LC.mutex.unlock("smtp.configure")
    return false, msg
  end

  -- restart smtp server
  if cfg.restart_cmd ~= nil then
    local rc = os.execute(cfg.restart_cmd)
    if rc ~= 0 then
      LC.mutex.unlock("smtp.configure")
      return false, "Error while reloading configuration (exit code: " .. rc .. ")"
    end
  end

  LC.mutex.unlock("smtp.configure")

  return true
end

-- ---------------------------------------------------------------------------
-- addMailbox()
--
-- Add mailboxes into smtp server config file
-- ---------------------------------------------------------------------------
function addMailbox(opts, data)
  LC.log.print(LC.log.DEBUG, "LC.smtp.addMailbox()")

  -- get configuration
  local cfg = getConfig(data.server)
  if cfg == nil then
    LC.log.print(LC.log.ERR, "SMTP server '", data.server, "' not found")
    return false, "SMTP server '" .. data.server .. "' not found"
  end

  if modlist[cfg.type] == nil then
    LC.log.print(LC.log.ERR, "No module for smtp server '", cfg.type, "' found")
    return false, "No module for smtp server '" .. cfg.type .. "' found"
  end

  -- run addMailbox() function from smtp server module
  LC.mutex.lock("smtp.configure")
  local ret = modlist[cfg.type].addMailbox(cfg, opts, data)
  LC.mutex.unlock("smtp.configure")

  return ret
end

-- ---------------------------------------------------------------------------
-- editMailbox()
--
-- Edit mailbox configuration
-- ---------------------------------------------------------------------------
function editMailbox(opts, data)
  LC.log.print(LC.log.DEBUG, "LC.smtp.editMailbox()")

  -- get configuration
  local cfg = getConfig(data.server)
  if cfg == nil then
    LC.log.print(LC.log.ERR, "SMTP server '", data.server, "' not found")
    return false, "SMTP server '" .. data.server .. "' not found"
  end

  if modlist[cfg.type] == nil then
    LC.log.print(LC.log.ERR, "No module for smtp server '", cfg.type, "' found")
    return false, "No module for smtp server '" .. cfg.type .. "' found"
  end

  -- run editMailbox() function from smtp server module
  LC.mutex.lock("smtp.configure")
  local ret = modlist[cfg.type].editMailbox(cfg, opts, data)
  LC.mutex.unlock("smtp.configure")

  return ret
end

-- ---------------------------------------------------------------------------
-- deleteMailbox()
--
-- Delete mailbox
-- ---------------------------------------------------------------------------
function deleteMailbox(opts, data)
  LC.log.print(LC.log.DEBUG, "LC.smtp.deleteMailbox()")

  -- get configuration
  local cfg = getConfig(data.server)
  if cfg == nil then
    LC.log.print(LC.log.ERR, "SMTP server '", data.server, "' not found")
    return false, "SMTP server '" .. data.server .. "' not found"
  end

  if modlist[cfg.type] == nil then
    LC.log.print(LC.log.ERR, "No module for smtp server '", cfg.type, "' found")
    return false, "No module for smtp server '" .. cfg.type .. "' found"
  end

  -- run deleteMailbox() function from smtp server module
  LC.mutex.lock("smtp.configure")
  local ret = modlist[cfg.type].deleteMailbox(cfg, opts, data)
  LC.mutex.unlock("smtp.configure")

  return ret
end

-- <EOF>----------------------------------------------------------------------
