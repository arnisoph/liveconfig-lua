--  _    _          ___           __ _     (R)
-- | |  (_)_ _____ / __|___ _ _  / _(_)__ _
-- | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
-- |____|_|\_/\___|\___\___/_||_|_| |_\__, |
--                                    |___/
-- Copyright (c) 2009-2012 Keppler IT GmbH.
-- ---------------------------------------------------------------------------
-- common/lua/cron.lua
-- Cron tab management
-- $Id: cron.lua 2888 2014-05-26 12:03:04Z kk $
-- ---------------------------------------------------------------------------

-- Imported functions
local LC = LC
local io = io
local os = os
local type = type
local ipairs = ipairs

-- Module declaration
module("cron")

-- Exported functions
--   update()

-- ---------------------------------------------------------------------------
-- update()
--
-- Update the cron table for a user
-- ---------------------------------------------------------------------------
function update(user, mailto, crontab)

  LC.log.print(LC.log.INFO, "Updating crontab for '", user, "'")

  local fh, msg = LC.popen("/usr/bin/crontab -u " .. user .. " -")
  if fh == nil then
    LC.log.print(LC.log.ERR, "Can't execute '/usr/bin/crontab -u ", user, " -': ", msg)
    return false, "Can't execute '/usr/bin/crontab -u ", user, " -': " .. msg
  end

  -- now write new crontab into this process:
  fh:write("# Crontab for user ", user, "\n")
  fh:write("# Automatically created by LiveConfig - DO NOT EDIT\n\n")

  if mailto == nil then
    fh:write("MAILTO=\"\"\n\n")
  else
    fh:write("MAILTO=\"", mailto, "\"\n\n")
  end

  if type(crontab) == "table" then
    local k, v
    for k, v in ipairs(crontab) do
      local line
      line = v["min"] .. " " .. v["hour"] .. " " .. v["day"] .. " " .. v["month"] .. " " .. v["dow"] .. "\t" .. v["cmd"]
      fh:write(line, "\n")
    end
  end

  fh:write("\n# <EOF>\n")
  -- close pipe:
  fh:close()

  -- read any output from STDERR
  while fh ~= nil do
    local line = fh:readErr()
    if line == nil then break end
    LC.log.print(LC.log.ERR, "CRON[" .. user .. "]: '" .. line .. "'")
  end

  local st = fh:wait()
  if st ~= 0 then
    LC.log.print(LC.log.ERR, "crontab(" .. user .. ") returned with exit code " .. st)
  end

  return true

end

-- ---------------------------------------------------------------------------
-- delete()
--
-- Delete cron tab for a user
-- ---------------------------------------------------------------------------
function delete(user)

  local rc = os.execute("/usr/bin/crontab -u " .. user .. " -r")

end

-- ---------------------------------------------------------------------------

-- register hooks
if LC.hooks then
  LC.hooks.add("LC.users.delUser", delete)
end

-- <EOF>----------------------------------------------------------------------
