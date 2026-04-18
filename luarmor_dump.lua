--[[ =====================================================================
    MARBEG HUB — LUARMOR V4 RUNTIME DUMPER
    Target executor: Delta (or any executor with hookfunction + writefile)

    USAGE:
      1. Paste this ENTIRE script into Delta
      2. Run it FIRST (before loading Luarmor/Marbeg Hub)
      3. Then run the Luarmor loader in the SAME execution (new tab ok):
           getgenv().script_key = "YOUR_KEY_HERE"
           loadstring(game:HttpGet("https://api.luarmor.net/..."))()
      4. Wait ~10-30 seconds — dumper captures all load/loadstring calls
      5. Press "SAVE NOW" on UI panel (or just wait, autosaves on capture)
      6. Outputs land in workspace/marbeg_dumps/ folder

    WHAT GETS CAPTURED:
      - Every `load()` / `loadstring()` / `loadfile()` call with its source
      - Every `readfile()` call (what Luarmor reads from static_content cache)
      - Every `writefile()` call (what Luarmor caches back)
      - `superflow_bytecode`, `_bsdata0[*]`, `script_key` globals snapshots
      - Arguments and (first 4KB of) return values of each hook

    OUTPUT STRUCTURE:
      workspace/marbeg_dumps/
        manifest.json                      -- index: {hash, origin, time, size}
        001_<hash>.lua                     -- 1st captured source
        002_<hash>.lua                     -- 2nd captured source  
        ...
        globals_snapshot_<N>.json          -- periodic global state dump
        readfile_log.json                  -- all readfile() calls logged
===================================================================== ]]--

if getgenv().__marbeg_dumper_active then
    warn("[MARBEG DUMPER] Already running. Re-run won't double-hook.")
    return
end
getgenv().__marbeg_dumper_active = true

-- ---------- 0. CONFIG ---------------------------------------------------
local CONFIG = {
    output_folder = "marbeg_dumps",
    max_capture_bytes = 16 * 1024 * 1024,  -- 16 MB cap per dump to avoid disk fill
    autosave_every_n_captures = 1,          -- save to disk after each capture
    snapshot_globals_every_sec = 5,         -- dump globals every 5s
    ui_position = UDim2.new(0, 20, 0, 100),
}

-- ---------- 1. EXECUTOR API DETECTION ----------------------------------
local hookfunction  = hookfunction or (syn and syn.hook) or (Krampus and Krampus.hook)
                     or (hookfunc) or error("[DUMPER] hookfunction unavailable — incompatible executor")
local writefile     = writefile     or error("[DUMPER] writefile unavailable")
local readfile_orig = readfile       -- may be nil if exec doesn't expose
local isfolder      = isfolder      or function() return false end
local makefolder    = makefolder    or function() end
local newcclosure   = newcclosure   or function(f) return f end
local identifyexecutor = identifyexecutor or function() return "unknown", "0.0" end

-- ---------- 2. WORKSPACE SETUP -----------------------------------------
if not isfolder(CONFIG.output_folder) then
    makefolder(CONFIG.output_folder)
end

local exec_name, exec_ver = identifyexecutor()
local start_epoch = os.time()
local start_label = os.date("%Y%m%d_%H%M%S")

-- ---------- 3. STATE ----------------------------------------------------
local state = {
    captures = {},          -- [n] = {hash, origin, time, size, chunk_name}
    readfile_log = {},      -- [n] = {path, time, size}
    writefile_log = {},     -- [n] = {path, time, size}
    capture_count = 0,
    dupe_hashes = {},       -- seen hash set to dedupe
    start_time = tick(),
}

-- ---------- 4. UTILITIES ------------------------------------------------
local function fnv1a(s)
    -- tiny, deterministic, dependency-free hash for dedupe + filenames
    if type(s) ~= "string" then s = tostring(s) end
    local h = 2166136261
    for i = 1, math.min(#s, 2048) do  -- sample first 2KB, enough to distinguish
        h = (h * 16777619) % 4294967296
        h = bit32.bxor(h, string.byte(s, i))
    end
    return string.format("%08x", h)
end

local function safe_tostring(v, max)
    max = max or 200
    local ok, s = pcall(tostring, v)
    if not ok then return "<tostring-error>" end
    if #s > max then return s:sub(1, max) .. "..<truncated>" end
    return s
end

local function get_caller_info()
    -- Get the script that called the hooked fn (approximate)
    local info = debug.getinfo(4, "Sn") or {}
    return {
        source = info.source or "=?",
        short  = info.short_src or "?",
        line   = info.currentline or 0,
        name   = info.name or "?",
    }
end

-- JSON encode helper (minimal, enough for our needs)
local function json_encode(v, depth)
    depth = depth or 0
    if depth > 6 then return '"<depth-limit>"' end
    local t = type(v)
    if t == "nil" then return "null"
    elseif t == "boolean" then return v and "true" or "false"
    elseif t == "number" then
        if v ~= v or v == math.huge or v == -math.huge then return "null" end
        return tostring(v)
    elseif t == "string" then
        return '"' .. v:gsub('[\\"%c]', function(c)
            local b = string.byte(c)
            if b == 0x22 then return '\\"'
            elseif b == 0x5C then return '\\\\'
            elseif b == 0x0A then return '\\n'
            elseif b == 0x0D then return '\\r'
            elseif b == 0x09 then return '\\t'
            elseif b < 0x20 then return string.format('\\u%04x', b)
            else return c end
        end) .. '"'
    elseif t == "table" then
        -- array or object?
        local n = 0
        for _ in pairs(v) do n = n + 1 end
        local len = #v
        if len == n and n > 0 then
            local parts = {}
            for i = 1, len do parts[i] = json_encode(v[i], depth + 1) end
            return "[" .. table.concat(parts, ",") .. "]"
        else
            local parts = {}
            for k, val in pairs(v) do
                parts[#parts + 1] = json_encode(tostring(k), depth + 1) .. ":" .. json_encode(val, depth + 1)
            end
            return "{" .. table.concat(parts, ",") .. "}"
        end
    end
    return '"<' .. t .. '>"'
end

local function write_json(path, data)
    local ok, err = pcall(writefile, path, json_encode(data))
    if not ok then warn("[DUMPER] write_json failed " .. tostring(err)) end
end

-- ---------- 5. CAPTURE ENGINE ------------------------------------------
local function save_manifest()
    write_json(CONFIG.output_folder .. "/manifest.json", {
        session_start = start_label,
        session_epoch = start_epoch,
        executor = exec_name,
        executor_ver = exec_ver,
        elapsed_sec = tick() - state.start_time,
        capture_count = state.capture_count,
        captures = state.captures,
    })
    write_json(CONFIG.output_folder .. "/readfile_log.json", state.readfile_log)
    write_json(CONFIG.output_folder .. "/writefile_log.json", state.writefile_log)
end

local function capture_source(origin, src, chunk_name)
    if type(src) ~= "string" then return end           -- bytecode / function — skip for now
    if #src < 32 then return end                        -- too small to be meaningful
    if #src > CONFIG.max_capture_bytes then
        src = src:sub(1, CONFIG.max_capture_bytes)
    end

    local h = fnv1a(src)
    if state.dupe_hashes[h] then return end             -- already captured
    state.dupe_hashes[h] = true

    state.capture_count = state.capture_count + 1
    local n = state.capture_count
    local filename = string.format("%03d_%s.lua", n, h)

    local info = {
        n = n,
        hash = h,
        origin = origin,
        chunk_name = chunk_name or "",
        size = #src,
        time = tick() - state.start_time,
        caller = get_caller_info(),
    }
    state.captures[#state.captures + 1] = info

    -- Write source with a header comment for human inspection
    local header = string.format(
        "--[[ MARBEG DUMP #%d\n  origin: %s\n  chunk:  %s\n  size:   %d bytes\n  hash:   %s\n  time:   %.2fs\n  caller: %s:%d (%s)\n]]--\n",
        n, origin, tostring(chunk_name), #src, h, info.time,
        info.caller.short, info.caller.line, info.caller.name
    )
    local ok = pcall(writefile, CONFIG.output_folder .. "/" .. filename, header .. src)
    if not ok then
        warn("[DUMPER] writefile failed for " .. filename)
    end

    if n % CONFIG.autosave_every_n_captures == 0 then
        save_manifest()
    end

    -- update UI if alive
    if state.update_ui then state.update_ui() end
end

-- ---------- 6. HOOKS ----------------------------------------------------
local original_loadstring = loadstring
local original_load       = load
local original_readfile   = readfile
local original_writefile  = writefile

-- loadstring hook (primary target for Luarmor final exec)
local loadstring_hook
loadstring_hook = hookfunction(loadstring, newcclosure(function(src, chunk)
    pcall(capture_source, "loadstring", src, chunk)
    return loadstring_hook(src, chunk)
end))

-- load hook (Lua 5.2+ style, also catches function-style loaders via chunks)
local load_hook
load_hook = hookfunction(load, newcclosure(function(chunk_or_fn, chunk_name, mode, env)
    if type(chunk_or_fn) == "string" then
        pcall(capture_source, "load", chunk_or_fn, chunk_name)
    elseif type(chunk_or_fn) == "function" then
        -- Function-loader: call it repeatedly, accumulate pieces
        local pieces, total = {}, 0
        local fn_loader = function()
            if total > CONFIG.max_capture_bytes then return nil end
            local piece = chunk_or_fn()
            if piece and #piece > 0 then
                pieces[#pieces + 1] = piece
                total = total + #piece
            end
            return piece
        end
        -- We can't double-consume; so wrap once and pass onward
        local ok, result, err = pcall(load_hook, fn_loader, chunk_name, mode, env)
        pcall(capture_source, "load(fn)", table.concat(pieces), chunk_name)
        if ok then return result, err end
        return nil, "dumper-wrap-error"
    end
    return load_hook(chunk_or_fn, chunk_name, mode, env)
end))

-- readfile hook — log cache reads
if original_readfile then
    local readfile_hook
    readfile_hook = hookfunction(readfile, newcclosure(function(path)
        local result = readfile_hook(path)
        pcall(function()
            state.readfile_log[#state.readfile_log + 1] = {
                path = tostring(path),
                size = type(result) == "string" and #result or 0,
                time = tick() - state.start_time,
            }
        end)
        return result
    end))
end

-- writefile hook — log cache writes (Luarmor writes to static_content)
local writefile_hook
writefile_hook = hookfunction(writefile, newcclosure(function(path, content)
    pcall(function()
        state.writefile_log[#state.writefile_log + 1] = {
            path = tostring(path),
            size = type(content) == "string" and #content or 0,
            time = tick() - state.start_time,
        }
    end)
    return writefile_hook(path, content)
end))

-- ---------- 7. GLOBAL WATCHERS -----------------------------------------
task.spawn(function()
    local snap_count = 0
    while state.start_time do
        task.wait(CONFIG.snapshot_globals_every_sec)
        snap_count = snap_count + 1

        local g = getgenv()
        local snapshot = {
            time = tick() - state.start_time,
            script_key = type(g.script_key) == "string" and g.script_key:sub(1, 80) or nil,
            superflow_bytecode = {
                exists = g.superflow_bytecode ~= nil,
                type = type(g.superflow_bytecode),
            },
            _bsdata0 = { exists = g._bsdata0 ~= nil, type = type(g._bsdata0) },
            _G_keys_of_interest = {},
        }

        -- Watch for Luarmor-typical globals
        for _, k in ipairs({
            "superflow_bytecode", "_bsdata0", "script_key",
            "KRNL_LOADED", "LRM_loaded", "LURMOR", "Luarmor",
        }) do
            if g[k] ~= nil or _G[k] ~= nil then
                snapshot._G_keys_of_interest[k] = type(g[k] or _G[k])
            end
        end

        -- If superflow_bytecode exists, snapshot its shape
        if type(g.superflow_bytecode) == "table" then
            local bc = g.superflow_bytecode
            snapshot.superflow_bytecode.size = #bc
            snapshot.superflow_bytecode.sample_types = {}
            for i = 1, math.min(#bc, 5) do
                snapshot.superflow_bytecode.sample_types[i] = type(bc[i])
                if type(bc[i]) == "string" then
                    snapshot.superflow_bytecode["sample_" .. i .. "_len"] = #bc[i]
                    snapshot.superflow_bytecode["sample_" .. i .. "_prefix"] =
                        bc[i]:sub(1, 40):gsub("[^%g ]", "?")
                end
            end
        end
        if type(g._bsdata0) == "table" then
            local bd = g._bsdata0
            snapshot._bsdata0.sample = {}
            for i = 1, 10 do
                if bd[i] ~= nil then
                    snapshot._bsdata0.sample[i] = {
                        type = type(bd[i]),
                        len = type(bd[i]) == "string" and #bd[i] or nil,
                        prefix = type(bd[i]) == "string" and bd[i]:sub(1, 40):gsub("[^%g ]", "?") or nil,
                    }
                end
            end
        end

        write_json(string.format("%s/globals_snapshot_%03d.json",
                                 CONFIG.output_folder, snap_count), snapshot)
    end
end)

-- ---------- 8. MINIMAL UI ----------------------------------------------
local ok_gui, err_gui = pcall(function()
    local CoreGui = gethui and gethui() or game:GetService("CoreGui")
    local gui = Instance.new("ScreenGui")
    gui.Name = "MarbegDumperUI"
    gui.ResetOnSpawn = false
    gui.DisplayOrder = 999999
    gui.Parent = CoreGui

    local frame = Instance.new("Frame", gui)
    frame.Size = UDim2.new(0, 260, 0, 140)
    frame.Position = CONFIG.ui_position
    frame.BackgroundColor3 = Color3.fromRGB(20, 22, 30)
    frame.BorderSizePixel = 0
    frame.Active = true
    frame.Draggable = true

    local corner = Instance.new("UICorner", frame)
    corner.CornerRadius = UDim.new(0, 6)

    local title = Instance.new("TextLabel", frame)
    title.Size = UDim2.new(1, -10, 0, 22)
    title.Position = UDim2.new(0, 5, 0, 4)
    title.BackgroundTransparency = 1
    title.Text = "MARBEG DUMPER — ACTIVE"
    title.TextColor3 = Color3.fromRGB(100, 230, 140)
    title.Font = Enum.Font.Code
    title.TextSize = 13
    title.TextXAlignment = Enum.TextXAlignment.Left

    local status = Instance.new("TextLabel", frame)
    status.Size = UDim2.new(1, -10, 0, 70)
    status.Position = UDim2.new(0, 5, 0, 28)
    status.BackgroundTransparency = 1
    status.Text = "Waiting for load()…"
    status.TextColor3 = Color3.fromRGB(220, 220, 220)
    status.Font = Enum.Font.Code
    status.TextSize = 11
    status.TextXAlignment = Enum.TextXAlignment.Left
    status.TextYAlignment = Enum.TextYAlignment.Top
    status.TextWrapped = true

    local btn = Instance.new("TextButton", frame)
    btn.Size = UDim2.new(1, -10, 0, 28)
    btn.Position = UDim2.new(0, 5, 1, -32)
    btn.BackgroundColor3 = Color3.fromRGB(40, 90, 60)
    btn.Text = "SAVE MANIFEST NOW"
    btn.TextColor3 = Color3.fromRGB(255, 255, 255)
    btn.Font = Enum.Font.Code
    btn.TextSize = 12
    btn.BorderSizePixel = 0
    local bc = Instance.new("UICorner", btn)
    bc.CornerRadius = UDim.new(0, 4)

    btn.MouseButton1Click:Connect(function()
        save_manifest()
        status.Text = status.Text .. "\n[manual save @ " .. string.format("%.1fs", tick() - state.start_time) .. "]"
    end)

    state.update_ui = function()
        local lines = {
            string.format("captures:  %d", state.capture_count),
            string.format("readfiles: %d", #state.readfile_log),
            string.format("writefiles:%d", #state.writefile_log),
            string.format("elapsed:   %.1fs", tick() - state.start_time),
        }
        if #state.captures > 0 then
            local last = state.captures[#state.captures]
            lines[#lines + 1] = string.format("last: %s (%d B)",
                last.origin:sub(1, 12), last.size)
        end
        status.Text = table.concat(lines, "\n")
    end
    state.update_ui()
end)

if not ok_gui then
    warn("[DUMPER] UI setup failed (non-fatal): " .. tostring(err_gui))
end

-- ---------- 9. READY ----------------------------------------------------
save_manifest()
print("[MARBEG DUMPER] armed. exec=" .. tostring(exec_name) ..
      "  folder=" .. CONFIG.output_folder ..
      "  now load Luarmor/Marbeg Hub in the SAME session.")
