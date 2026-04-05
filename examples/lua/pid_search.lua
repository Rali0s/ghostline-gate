local query = table.concat(arg, " ")
local command = "./build-local/ghostline_cli --search-json " .. query
local handle = io.popen(command, "r")
if not handle then
  io.stderr:write("failed to run ghostline_cli\n")
  os.exit(1)
end

local output = handle:read("*a")
handle:close()

for pid, cmd in output:gmatch('"pid"%s*:%s*(%d+).-"command"%s*:%s*"([^"]+)"') do
  print(string.format("PID %s command=%s", pid, cmd))
end

