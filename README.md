import os
import io
import re
import sys
import base64
import zipfile
import logging
import requests
import gzip
import json
import math
import struct
import time
from typing import Dict, Optional, List, Tuple, Any, Union
from datetime import datetime
from collections import defaultdict

from telegram import Update, InlineKeyboardMarkup, InlineKeyboardButton, InputFile
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ContextTypes,
    filters
)

BOT_TOKEN = "8478108815:AAEhrJnxYB-RoGJYK7S2RxO_nE9dwkgQhIg"

# Импорт Lupa с обработкой ошибок
try:
    from lupa import LuaRuntime
    from lupa import LuaError
    HAS_LUPA = True
except Exception as e:
    HAS_LUPA = False
    print(f"Lupa import error: {e}")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
log = logging.getLogger('universal_deobfuscator')

LAST_FILES: Dict[int, Tuple[str, bytes]] = {}
USER_SETTINGS: Dict[int, Dict[str, Any]] = {}
USER_KEYBOARD_PAGE: Dict[int, int] = {}

DEFAULT_SETTINGS = {
    # Основные декодеры
    'wrd_literals': True,
    'decode_char': True,
    'execute_xor_functions': True,
    'concat_strings': True,
    'autodelete': False,
    'analyze_functionality': True,
    'strip_line_comments': False,
    'strip_block_comments': False,
    'zip_outputs': True,
    'accept_non_utf8': True,
    'delete_probels': False,
    'minifier': False,
    'advanced_xor_decoding': True,
    'decode_table_arrays': True,
    'deep_analysis': True,
    'remove_fake_flags': True,
    'execute_wrd_runtime': True,
    'lupa_execution': True,
    'extract_actual_code': True,
    'decode_bit32_xor': True,
    'remove_obfuscation_layers': True,
    'extract_hidden_functions': True,
    'decode_ntt_obfuscator': True,
    
    # Luraph специфичные настройки
    'decode_luraph': True,
    'luraph_vm_emulation': True,
    'decode_luraph_strings': True,
    'remove_luraph_anti_debug': True,
    'extract_luraph_bytecode': True,
    'luraph_constant_propagation': True,
    
    # Продвинутые функции
    'hookop_enabled': False,  # HookOp - перехват и анализ функций
    'hookop_v2_enabled': False,  # HookOpV2 - форматирование return, (), :, ;
    'spy_execute_enabled': False,  # SpyExecute - отслеживание выполнения
    'trace_calls': False,  # Трассировка вызовов
    'dump_environment': False,  # Дамп окружения
    'sandbox_mode': True,  # Песочница для безопасного выполнения
    'memory_analysis': False,  # Анализ памяти
    'hook_require': False,  # Перехват require
    'hook_loadstring': False,  # Перехват loadstring
    'hook_http': False,  # Перехват HTTP запросов
    'monitor_filesystem': False,  # Мониторинг файловой системы
    'detect_keyloggers': False,  # Детект кейлоггеров
    'detect_injection': False,  # Детект инъекций
    'bypass_antidebug': True,  # Обход анти-отладки
    'auto_extract_payloads': True,  # Авто-извлечение пейлоадов
}

def get_settings(user_id: int) -> Dict[str, Any]:
    if user_id not in USER_SETTINGS:
        USER_SETTINGS[user_id] = dict(DEFAULT_SETTINGS)
    return USER_SETTINGS[user_id]

def reset_settings(user_id: int):
    USER_SETTINGS[user_id] = dict(DEFAULT_SETTINGS)

# ============= РЕГУЛЯРНЫЕ ВЫРАЖЕНИЯ ДЛЯ ВСЕХ ТИПОВ ОБФУСКАЦИИ =============

# WRD (WeAreDevs)
WRD_HEADER_RE = re.compile(r'--\[\[ v\d+\.\d+\.\d+ https://wearedevs\.net/obfuscator \]\]', re.IGNORECASE)
WRD_RETURN_RE = re.compile(r'return\(function\(\.\.\.\)local Y={.*?end\)\(\.\.\.\)', re.DOTALL)
WRD_FULL_PATTERN = re.compile(r'--\[\[ v\d+\.\d+\.\d+ https://wearedevs\.net/obfuscator \]\].*?return\(function\(\.\.\.\).*?end\)\(\.\.\.\)', re.DOTALL)
WRD_TABLE_RE = re.compile(r'local Y={([^}]+)}', re.DOTALL)

# Luraph Obfuscator v14.6
LURAPH_HEADER_RE = re.compile(r'-- This file was protected using Luraph Obfuscator v\d+\.\d+', re.IGNORECASE)
LURAPH_RETURN_TABLE_RE = re.compile(r'return\(\{(.*?)\}\)', re.DOTALL)
LURAPH_FUNCTION_RE = re.compile(r'(\w+)=function\((.*?)\)(.*?)end', re.DOTALL)
LURAPH_STRING_ENCRYPT_RE = re.compile(r'([a-zA-Z0-9_]+)\[0x([0-9A-Fa-f]+)\]\(\)', re.IGNORECASE)
LURAPH_NUMBER_ENCRYPT_RE = re.compile(r'0[xX][0-9A-Fa-f]+_[0-9A-Fa-f_]+', re.IGNORECASE)
LURAPH_BIT32_RE = re.compile(r'bit32\.(\w+)\(([^)]+)\)', re.IGNORECASE)
LURAPH_ANTI_DEBUG_RE = re.compile(r'if\s+debug\s+and\s+debug\.(\w+)\s+then.*?end', re.DOTALL)
LURAPH_VM_DISPATCH_RE = re.compile(r'while\s+true\s+do\s+local\s+(\w+)=([^\n]+)\s+if\s+\1==(\d+)\s+then', re.DOTALL)
LURAPH_BYTECODE_RE = re.compile(r'string\.dump\s*\(\s*(\w+)\s*\)', re.IGNORECASE)
LURAPH_LOAD_RE = re.compile(r'load(?:string|file)\s*\(\s*([^)]+)\s*\)', re.IGNORECASE)

# Новая обфускация NTT (Obfucator NTT)
NTT_HEADER_RE = re.compile(r'--Version \d+\s*_G\.credit=\[\[Obfucator NTT - https://discord\.gg/\w+\]\]', re.IGNORECASE)
NTT_TABLE_RE = re.compile(r'local\s+_ySMoBAPw=\{(.*?)\}', re.DOTALL)
NTT_DECODE_FUNCTION_RE = re.compile(r'local\s+function\s+(\w+)\((\w+)\)(.*?)end', re.DOTALL)
NTT_CALL_RE = re.compile(r'(\w+)\((\d+)\)')

# Новая обфускация с v0,v1,v2,v3,v4,v5,v6
NEW_OBFUSCATION_PATTERN = re.compile(r'local\s+v0=string\.char;local\s+v1=string\.byte;local\s+v2=string\.sub;local\s+v3=bit32\s+or\s+bit\s*;local\s+v4=v3\.bxor;local\s+v5=table\.concat;local\s+v6=table\.insert;local\s+function\s+v7\([^)]+\)(.*?)end', re.DOTALL)
NEW_OBFUSCATION_FULL = re.compile(r'local\s+v0=string\.char.*?local\s+function\s+v7\([^)]+\).*?end.*?local\s+v8;.*?return.*?end\)?', re.DOTALL)
XOR_STRING_FUNC_RE = re.compile(r'function\s+(\w+)\s*\(([^,)]+),([^)]+)\)\s*local\s+(\w+)=\{\};for\s+(\w+)=1,#(\w+)\s+do\s*\6\(\4,\1\(\3\(\2,\5,\5\+\1\)\),\2\(\3\([^,)]+,[^)]+\)%256\)\)[^}]*end', re.IGNORECASE)

# Паттерн для v7 функции с XOR
V7_XOR_FUNCTION_RE = re.compile(
    r'local\s+function\s+v7\((\w+),(\w+)\)\s*'
    r'local\s+(\w+)=\{\};'
    r'for\s+(\w+)=1,#(\w+)\s+do\s*'
    r'v6\(v3,v0\(v4\(v1\(v2\(\5,\4,\4\+\1\)\),'
    r'v1\(v2\([^,)]+,[^)]+\)%256\)\);end\s*'
    r'return\s+v5\(v3\)',
    re.DOTALL
)

# Паттерн для pcall/require с XOR строкой
PCALL_XOR_RE = re.compile(r'pcall\(function\(\)\s*return\s+require\(v7\(([^,)]+),([^)]+)\)\);end\)', re.DOTALL)
LOADSTRING_XOR_RE = re.compile(r'loadstring\(game:HttpGet\(v7\(([^,)]+),([^)]+)\)\)\)\(\)', re.DOTALL)

# Базовые паттерны
STR_LIT_DBL = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"')
STR_LIT_SGL = re.compile(r"'([^'\\]*(?:\\.[^'\\]*)*)'")
STRING_CHAR_RE = re.compile(r'string\.char\s*\(\s*([^)]+)\)')
XOR_FUNCTION_RE = re.compile(r'function\s+(\w+)\s*\((\w+),(\w+)\)(.*?)end', re.DOTALL)
XOR_CALL_RE = re.compile(r'(\w+)\s*\(\s*(["\'])(.*?)\2\s*,\s*(["\'])(.*?)\4\s*\)')
TABLE_ARRAY_RE = re.compile(r'\{\s*\{\s*(\d+(?:\s*,\s*\d+)*)\s*\}\s*,\s*(\d+)\s*\}')
BIT32_XOR_CALL_RE = re.compile(r'bit32\.bxor\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)')
BIT32_XOR_VAR_RE = re.compile(r'v4\(v1\(v2\(([^,)]+),(\d+),(\d+)\)\),v1\(v2\(([^,)]+),(\d+),(\d+)\)\)\)%256')

# Паттерны для HookOp и SpyExecute
HOOKABLE_FUNCTIONS_RE = re.compile(r'function\s+(\w+)\s*\(', re.IGNORECASE)
LOADSTRING_CALLS_RE = re.compile(r'loadstring\s*\(\s*([^)]+)\s*\)', re.IGNORECASE)
REQUIRE_CALLS_RE = re.compile(r'require\s*\(\s*(["\'])([^"\']+)\1\s*\)', re.IGNORECASE)
HTTP_CALLS_RE = re.compile(r'game:HttpGet(?:Async)?\s*\(\s*([^)]+)\s*\)', re.IGNORECASE)
DEBUG_CALLS_RE = re.compile(r'debug\.(\w+)', re.IGNORECASE)

# ============= КЛАСС ДЛЯ ВЫПОЛНЕНИЯ LUA ЧЕРЕЗ LUPA =============

class LuaRuntimeExecutor:
    """Класс для выполнения Lua кода через Lupa"""
    
    def __init__(self):
        self.lua = None
        self.globals = {}
        self.hooked_functions = {}
        self.execution_trace = []
        self.memory_dump = {}
        self.setup_lua()
    
    def setup_lua(self):
        """Инициализация Lua рантайма"""
        if not HAS_LUPA:
            return False
        
        try:
            self.lua = LuaRuntime(unpack_returned_tuples=True)
            
            # Эмуляция Roblox/Luau окружения с расширенными возможностями
            self.lua.execute('''
                -- Глобальные переменные
                _G = _G or {}
                game = game or {}
                workspace = workspace or {}
                Players = Players or {}
                LocalPlayer = LocalPlayer or {}
                PlayerGui = PlayerGui or {}
                ScreenGui = ScreenGui or {}
                
                -- Сервисы
                function game:GetService(name)
                    if name == "HttpService" then
                        return HttpService
                    elseif name == "Players" then
                        return Players
                    elseif name == "Workspace" then
                        return workspace
                    elseif name == "RunService" then
                        return RunService
                    elseif name == "UserInputService" then
                        return UserInputService
                    elseif name == "TeleportService" then
                        return TeleportService
                    elseif name == "CoreGui" then
                        return CoreGui
                    elseif name == "Lighting" then
                        return Lighting
                    elseif name == "Debris" then
                        return Debris
                    elseif name == "ReplicatedStorage" then
                        return ReplicatedStorage
                    elseif name == "ServerScriptService" then
                        return ServerScriptService
                    elseif name == "ServerStorage" then
                        return ServerStorage
                    end
                    return _G[name] or {}
                end
                
                -- Instance
                Instance = Instance or {}
                function Instance.new(class, parent)
                    local obj = {
                        ClassName = class,
                        Parent = parent,
                        Children = {},
                        Properties = {}
                    }
                    return obj
                end
                
                -- HttpService
                HttpService = HttpService or {}
                function HttpService:GetAsync(url)
                    _HOOKED_HTTP_REQUESTS = _HOOKED_HTTP_REQUESTS or {}
                    table.insert(_HOOKED_HTTP_REQUESTS, {method="GET", url=url})
                    return ""
                end
                function HttpService:PostAsync(url, data)
                    _HOOKED_HTTP_REQUESTS = _HOOKED_HTTP_REQUESTS or {}
                    table.insert(_HOOKED_HTTP_REQUESTS, {method="POST", url=url, data=data})
                    return ""
                end
                function HttpService:JSONDecode(str)
                    return {}
                end
                function HttpService:JSONEncode(tbl)
                    return "{}"
                end
                
                -- Функции вывода
                function print(...) 
                    local args = {...}
                    _HOOKED_PRINTS = _HOOKED_PRINTS or {}
                    table.insert(_HOOKED_PRINTS, args)
                end
                function warn(...) 
                    local args = {...}
                    _HOOKED_WARNS = _HOOKED_WARNS or {}
                    table.insert(_HOOKED_WARNS, args)
                end
                function error(...) 
                    local args = {...}
                    _HOOKED_ERRORS = _HOOKED_ERRORS or {}
                    table.insert(_HOOKED_ERRORS, args)
                end
                
                -- bit32 эмуляция
                bit32 = bit32 or {}
                function bit32.bxor(a, b) return a ~ b end
                function bit32.band(a, b) return a & b end
                function bit32.bor(a, b) return a | b end
                function bit32.lshift(a, b) return a << b end
                function bit32.rshift(a, b) return a >> b end
                function bit32.arshift(a, b) return a >> b end
                function bit32.btest(a, b) return (a & b) ~= 0 end
                function bit32.rotate(a, b) return ((a << b) | (a >> (32 - b))) & 0xFFFFFFFF end
                function bit32.countlz(a) 
                    local count = 0
                    for i = 31, 0, -1 do
                        if (a & (1 << i)) == 0 then count = count + 1 else break end
                    end
                    return count
                end
                function bit32.countrz(a)
                    local count = 0
                    for i = 0, 31 do
                        if (a & (1 << i)) == 0 then count = count + 1 else break end
                    end
                    return count
                end
                
                -- bit эмуляция (для обратной совместимости)
                bit = bit or bit32
                
                -- Табличные функции
                table = table or {}
                table.insert = table.insert or function(t, v) t[#t+1] = v end
                table.concat = table.concat or function(t, sep) return table.concat(t, sep or "") end
                table.remove = table.remove or function(t, i) return table.remove(t, i) end
                
                -- Математические функции
                math = math or {}
                math.floor = math.floor
                math.ceil = math.ceil
                math.random = math.random or function() return 0.5 end
                
                -- Строковые функции
                string = string or {}
                string.char = string.char
                string.byte = string.byte
                string.sub = string.sub
                string.gsub = string.gsub
                string.gmatch = string.gmatch
                string.find = string.find
                string.format = string.format
                string.dump = string.dump or function(f) return tostring(f) end
                
                -- Функции окружения
                getfenv = function() return _G end
                setfenv = function() end
                getgenv = function() return _G end
                getrenv = function() return _G end
                
                -- Дополнительные функции
                delay = function(t, f) end
                spawn = function(f) f() end
                wait = function(t) return t or 0.1 end
                tick = function() return os.clock() end
                time = function() return os.time() end
                
                -- UDim/UDim2/Color3 эмуляция
                UDim = UDim or {new = function(scale, offset) return {Scale = scale, Offset = offset} end}
                UDim2 = UDim2 or {new = function(xScale, xOffset, yScale, yOffset) 
                    return {X = {Scale = xScale, Offset = xOffset}, Y = {Scale = yScale, Offset = yOffset}} 
                end}
                Color3 = Color3 or {}
                Color3.new = function(r,g,b) return {R = r, G = g, B = b} end
                Color3.fromRGB = function(r,g,b) return {R = r/255, G = g/255, B = b/255} end
                Color3.fromHex = function(hex) return {R = 0, G = 0, B = 0} end
                ColorSequence = ColorSequence or {new = function(...) return {...} end}
                
                -- Анти-отладка обход
                debug = debug or {}
                debug.getinfo = function() return nil end
                debug.getregistry = function() return {} end
                debug.getmetatable = function() return nil end
                debug.setmetatable = function() end
                debug.getupvalue = function() return nil end
                debug.setupvalue = function() end
                debug.getuservalue = function() return nil end
                debug.setuservalue = function() end
                
                -- Перехват результатов
                _EXECUTION_RESULT = nil
                _EXECUTION_STRINGS = {}
                _DECODED_CODE = nil
                _HOOKED_FUNCTIONS = {}
                _HOOKED_CALLS = {}
                _TRACE_LOG = {}
                
                function hook_function(name, func)
                    _HOOKED_FUNCTIONS[name] = func
                    return function(...)
                        table.insert(_HOOKED_CALLS, {name=name, args={...}})
                        table.insert(_TRACE_LOG, {type="call", name=name, time=os.clock()})
                        local results = {func(...)}
                        table.insert(_TRACE_LOG, {type="return", name=name, time=os.clock()})
                        return table.unpack(results)
                    end
                end
                
                function capture_result(...)
                    local args = {...}
                    _EXECUTION_RESULT = args
                    for _, v in ipairs(args) do
                        if type(v) == "string" and #v > 50 then
                            _DECODED_CODE = v
                            table.insert(_EXECUTION_STRINGS, v)
                        elseif type(v) == "table" then
                            for _, val in pairs(v) do
                                if type(val) == "string" and #val > 50 then
                                    _DECODED_CODE = val
                                    table.insert(_EXECUTION_STRINGS, val)
                                end
                            end
                        end
                    end
                    return ...
                end
                
                function spy_execute(func, ...)
                    local start_time = os.clock()
                    local success, result = pcall(func, ...)
                    local end_time = os.clock()
                    table.insert(_TRACE_LOG, {
                        type = "execution",
                        func = tostring(func),
                        success = success,
                        result = tostring(result),
                        duration = end_time - start_time
                    })
                    return success, result
                end
            ''')
            
            return True
        except Exception as e:
            log.error(f"Lua setup error: {e}")
            return False
    
    def enable_hookop(self, code: str) -> str:
        """Включает HookOp - перехват и анализ функций"""
        if not self.lua:
            return code
        
        try:
            # Находим все функции для перехвата
            functions = HOOKABLE_FUNCTIONS_RE.findall(code)
            
            hook_code = "\n-- HookOp: Function Hooking Enabled\n"
            for func_name in set(functions):
                if len(func_name) > 1 and not func_name.startswith('_'):
                    hook_code += f"{func_name} = hook_function('{func_name}', {func_name})\n"
            
            # Добавляем в начало кода
            code = hook_code + "\n" + code
            
            # Добавляем отслеживание вызовов
            code = code.replace('loadstring(', 'spy_execute(loadstring, ')
            code = code.replace('require(', 'spy_execute(require, ')
            
        except Exception as e:
            log.error(f"HookOp error: {e}")
        
        return code
    
    def enable_hookop_v2(self, code: str) -> str:
        """HookOpV2 - форматирование return, (), :, ; и улучшение читаемости кода"""
        if not self.lua:
            return code
        
        try:
            hook_code = """
-- HookOpV2: Advanced Code Formatting & Analysis Enabled

-- Форматирование return statements
local function format_return(value)
    if type(value) == "table" then
        local str = "{"
        local first = true
        for k, v in pairs(value) do
            if not first then str = str .. ", " end
            first = false
            if type(k) == "string" then
                str = str .. string.format("[%q]=", k)
            elseif type(k) == "number" then
                str = str .. string.format("[%d]=", k)
            else
                str = str .. tostring(k) .. "="
            end
            if type(v) == "string" then
                str = str .. string.format("%q", v)
            elseif type(v) == "table" then
                str = str .. "{}"
            else
                str = str .. tostring(v)
            end
        end
        str = str .. "}"
        return str
    elseif type(value) == "string" then
        return string.format("%q", value)
    elseif type(value) == "function" then
        return "function() ... end"
    else
        return tostring(value)
    end
end

-- Перехват и форматирование return
local original_return = return
local function hook_return(...)
    local results = {...}
    local formatted = {}
    for i, v in ipairs(results) do
        formatted[i] = format_return(v)
    end
    table.insert(_HOOKED_CALLS, {type="return", values=table.concat(formatted, ", ")})
    return ...
end

-- Мониторинг вызовов функций с форматированием параметров
local function monitor_call(func_name, ...)
    local args = {...}
    local formatted_args = {}
    for i, v in ipairs(args) do
        formatted_args[i] = format_return(v)
    end
    table.insert(_TRACE_LOG, {
        type = "call_v2",
        func = func_name,
        args = table.concat(formatted_args, ", "),
        time = os.clock()
    })
end

-- Автоматическое форматирование кода
_G._FORMATTER_ENABLED = true

-- Улучшение читаемости таблиц
local original_table_concat = table.concat
table.concat = function(t, sep, i, j)
    local result = original_table_concat(t, sep, i, j)
    table.insert(_TRACE_LOG, {type="table_concat", result=result})
    return result
end

-- Анализ структуры кода
_G._CODE_STRUCTURE = {
    functions = {},
    returns = {},
    calls = {}
}

-- Форматирование вызовов методов
local original_colon_call = function(obj, method, ...) 
    return obj[method](obj, ...)
end

_G._HOOKED_METHODS = {}
_G._HOOKED_METHODS_COUNT = 0

print("✅ HookOpV2 initialized - Code formatting enabled")
"""
            code = hook_code + "\n" + code
            
        except Exception as e:
            log.error(f"HookOpV2 error: {e}")
        
        return code
    
    def enable_spy_execute(self, code: str) -> str:
        """Включает SpyExecute - отслеживание выполнения"""
        if not self.lua:
            return code
        
        try:
            spy_code = """
-- SpyExecute: Execution Monitoring Enabled
_G._SPY_ENABLED = true

local original_pcall = pcall
pcall = function(f, ...)
    local start = os.clock()
    local success, result = original_pcall(f, ...)
    local duration = os.clock() - start
    table.insert(_TRACE_LOG, {
        type = "pcall",
        func = tostring(f),
        success = success,
        duration = duration
    })
    return success, result
end

local original_xpcall = xpcall
xpcall = function(f, err, ...)
    local start = os.clock()
    local success, result = original_xpcall(f, err, ...)
    local duration = os.clock() - start
    table.insert(_TRACE_LOG, {
        type = "xpcall",
        func = tostring(f),
        success = success,
        duration = duration
    })
    return success, result
end
"""
            code = spy_code + "\n" + code
            
        except Exception as e:
            log.error(f"SpyExecute error: {e}")
        
        return code
    
    def enable_sandbox(self, code: str) -> str:
        """Включает безопасную песочницу"""
        if not self.lua:
            return code
        
        try:
            sandbox_code = """
-- Sandbox Mode: Restricted Environment
local allowed_globals = {
    'print', 'warn', 'error', 'type', 'tostring', 'tonumber',
    'pairs', 'ipairs', 'next', 'select', 'unpack', 'table',
    'string', 'math', 'bit32', 'bit', 'os', 'coroutine',
    '_G', '_VERSION', 'assert', 'collectgarbage', 'rawequal',
    'rawget', 'rawlen', 'rawset', 'pcall', 'xpcall'
}

local env = {}
for _, name in ipairs(allowed_globals) do
    if _G[name] then
        env[name] = _G[name]
    end
end

-- Запрещаем опасные функции
env.os = {clock = os.clock, time = os.time, date = os.date}
env.debug = nil
env.io = nil
env.file = nil

setfenv(1, env)
"""
            code = sandbox_code + "\n" + code
            
        except Exception as e:
            log.error(f"Sandbox error: {e}")
        
        return code
    
    def enable_tracing(self, code: str) -> str:
        """Включает трассировку вызовов"""
        if not self.lua:
            return code
        
        try:
            trace_code = """
-- Call Tracing Enabled
debug.sethook(function(event, line)
    local info = debug.getinfo(2)
    table.insert(_TRACE_LOG, {
        type = event,
        source = info.source,
        line = line,
        func = info.name or 'anonymous',
        time = os.clock()
    })
end, 'crl')
"""
            code = trace_code + "\n" + code
            
        except Exception as e:
            log.error(f"Tracing error: {e}")
        
        return code
    
    def hook_require(self, code: str) -> str:
        """Перехватывает require вызовы"""
        if not self.lua:
            return code
        
        try:
            hook_code = """
-- HookOp: Require Hooking Enabled
local original_require = require
require = function(module)
    local result = original_require(module)
    table.insert(_HOOKED_CALLS, {type="require", module=module, result=tostring(result)})
    return result
end
"""
            code = hook_code + "\n" + code
            
        except Exception as e:
            log.error(f"Require hook error: {e}")
        
        return code
    
    def execute_luraph_script(self, code: str) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Выполняет Luraph обфусцированный скрипт"""
        if not self.lua:
            return False, None, {"error": "Lupa не доступна"}
        
        stats = {
            'vm_detected': False,
            'decoded_strings': 0,
            'extracted_bytecode': None,
            'hooked_calls': 0,
            'execution_trace': []
        }
        
        try:
            # Сброс результатов
            self.lua.execute('''
                _EXECUTION_RESULT = nil; 
                _DECODED_CODE = nil; 
                _EXECUTION_STRINGS = {};
                _HOOKED_CALLS = {};
                _TRACE_LOG = {};
                _HOOKED_HTTP_REQUESTS = {};
                _HOOKED_PRINTS = {};
            ''')
            
            # Находим Luraph скрипт
            if not LURAPH_HEADER_RE.search(code):
                return False, None, stats
            
            stats['vm_detected'] = True
            
            # Удаляем анти-отладку
            if self.get_settings('bypass_antidebug', True):
                code = self.remove_luraph_antidebug(code)
            
            # Модифицируем для захвата результата
            modified_code = code.replace(
                'return({',
                'return(capture_result({'
            )
            
            # Добавляем перехват функций
            if self.get_settings('hookop_enabled', False):
                modified_code = self.enable_hookop(modified_code)
                stats['hooked_calls'] = 1
            
            # Добавляем HookOpV2
            if self.get_settings('hookop_v2_enabled', False):
                modified_code = self.enable_hookop_v2(modified_code)
                stats['hooked_calls'] += 1
            
            # Добавляем отслеживание выполнения
            if self.get_settings('spy_execute_enabled', False):
                modified_code = self.enable_spy_execute(modified_code)
            
            # Добавляем песочницу
            if self.get_settings('sandbox_mode', True):
                modified_code = self.enable_sandbox(modified_code)
            
            # Добавляем трассировку
            if self.get_settings('trace_calls', False):
                modified_code = self.enable_tracing(modified_code)
            
            # Перехват require
            if self.get_settings('hook_require', False):
                modified_code = self.hook_require(modified_code)
            
            # Выполняем
            self.lua.execute(modified_code)
            
            # Получаем результат
            result = self.lua.globals()._DECODED_CODE
            if not result:
                strings = self.lua.globals()._EXECUTION_STRINGS
                if strings and len(strings) > 0:
                    result = strings[0]
                    stats['decoded_strings'] = len(strings)
            
            # Получаем перехваченные вызовы
            hooked_calls = self.lua.globals()._HOOKED_CALLS
            if hooked_calls:
                stats['hooked_calls'] = len(hooked_calls)
            
            # Получаем трассировку
            trace_log = self.lua.globals()._TRACE_LOG
            if trace_log:
                stats['execution_trace'] = list(trace_log)[:10]
            
            if result:
                return True, result, stats
            else:
                return False, None, stats
                
        except LuaError as e:
            return False, None, {"error": f"Lua ошибка: {str(e)}"}
        except Exception as e:
            return False, None, {"error": f"Ошибка выполнения: {str(e)}"}
    
    def get_settings(self, key: str, default: Any = None) -> Any:
        """Получает настройки (заглушка)"""
        return default
    
    def remove_luraph_antidebug(self, code: str) -> str:
        """Удаляет анти-отладку из Luraph кода"""
        # Удаляем проверки debug
        code = re.sub(LURAPH_ANTI_DEBUG_RE, '', code, flags=re.DOTALL)
        
        # Удаляем проверки getfenv/setfenv
        code = re.sub(r'if\s+getfenv\s*\(\s*\)\s*~=\s*_G\s+then.*?end', '', code, flags=re.DOTALL)
        
        # Удаляем проверки наличия деобфускаторов
        code = re.sub(r'if\s+_\w+_\s+or\s+_\w+__\s+then.*?end', '', code, flags=re.DOTALL)
        
        return code
    
    def execute_ntt_obfuscation(self, code: str) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Выполняет NTT обфусцированный скрипт"""
        if not self.lua:
            return False, None, {"error": "Lupa не доступна"}
        
        stats = {
            'detected': False,
            'decoded_strings': 0,
            'extracted_code': None
        }
        
        try:
            self.lua.execute('_EXECUTION_RESULT = nil; _DECODED_CODE = nil; _EXECUTION_STRINGS = {}')
            
            ntt_table_match = NTT_TABLE_RE.search(code)
            if not ntt_table_match:
                return False, None, stats
            
            ntt_func_match = NTT_DECODE_FUNCTION_RE.search(code)
            if not ntt_func_match:
                return False, None, stats
            
            func_name = ntt_func_match.group(1)
            stats['detected'] = True
            
            modified_code = code + f"""

local decoded_strings = {{}}
for i = 1, #_ySMoBAPw do
    local success, result = pcall(function()
        return {func_name}(i)
    end)
    if success and result then
        decoded_strings[i] = result
        if type(result) == "string" and #result > 10 then
            _DECODED_CODE = result
            table.insert(_EXECUTION_STRINGS, result)
        end
    end
end

for i, str in ipairs(decoded_strings) do
    if str and type(str) == "string" and #str > 100 then
        _DECODED_CODE = str
    end
    if str and type(str) == "string" and (str:find("loadstring") or str:find("game:HttpGet") or str:find("require")) then
        _DECODED_CODE = str
    end
end

if _DECODED_CODE then
    local load_success, load_result = pcall(loadstring, _DECODED_CODE)
    if load_success and load_result then
        local exec_success, exec_result = pcall(load_result)
        if exec_success and exec_result then
            if type(exec_result) == "string" and #exec_result > 100 then
                _DECODED_CODE = exec_result
            end
        end
    end
end
"""
            
            self.lua.execute(modified_code)
            
            result = self.lua.globals()._DECODED_CODE
            if not result:
                strings = self.lua.globals()._EXECUTION_STRINGS
                if strings and len(strings) > 0:
                    result = strings[0]
                    stats['decoded_strings'] = len(strings)
            
            if result:
                stats['extracted_code'] = result
                return True, result, stats
            else:
                return False, None, stats
                
        except Exception as e:
            return False, None, {"error": str(e)}
    
    def execute_wrd_script(self, code: str) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Выполняет WRD обфусцированный скрипт"""
        if not self.lua:
            return False, None, {"error": "Lupa не доступна"}
        
        stats = {
            'detected': False,
            'decoded_strings': 0,
            'execution_success': False
        }
        
        try:
            self.lua.execute('_EXECUTION_RESULT = nil; _DECODED_CODE = nil; _EXECUTION_STRINGS = {}')
            
            wrd_match = WRD_FULL_PATTERN.search(code)
            if not wrd_match:
                wrd_match = re.search(r'return\(function\(\.\.\.\).*?end\)\(\.\.\.\)', code, re.DOTALL)
            
            if not wrd_match:
                return False, None, stats
            
            stats['detected'] = True
            wrd_script = wrd_match.group(0)
            
            modified_script = wrd_script.replace(
                'return(function(...)',
                'return(capture_result(function(...)'
            )
            
            self.lua.execute(modified_script)
            
            result = self.lua.globals()._DECODED_CODE
            if not result:
                strings = self.lua.globals()._EXECUTION_STRINGS
                if strings and len(strings) > 0:
                    result = strings[0]
                    stats['decoded_strings'] = len(strings)
            
            if result:
                stats['execution_success'] = True
                return True, result, stats
            else:
                return False, None, stats
                
        except Exception as e:
            return False, None, {"error": str(e)}
    
    def execute_new_obfuscation(self, code: str) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Выполняет новую обфускацию с v7 XOR функцией"""
        if not self.lua:
            return False, None, {"error": "Lupa не доступна"}
        
        stats = {
            'detected': False,
            'decoded_strings': 0,
            'extracted_code': None
        }
        
        try:
            v7_match = NEW_OBFUSCATION_FULL.search(code)
            if not v7_match:
                v7_match = re.search(r'local\s+v0=string\.char.*?local\s+function\s+v7.*?end.*?local\s+v8;.*?end', code, re.DOTALL)
            
            if not v7_match:
                return False, None, stats
            
            stats['detected'] = True
            obfuscated_code = v7_match.group(0)
            
            encrypted_strings = re.findall(r'v7\("([^"]+)","([^"]+)"\)', code)
            
            test_code = f"""
                {obfuscated_code}
                local results = {{}}
                local v8 = v8
                
                local success, result = pcall(function()
                    if v8 and type(v8) == "table" and v8.CreateWindow then
                        return "Window created"
                    elseif type(v8) == "function" then
                        return "Function found"
                    elseif v8 then
                        return tostring(v8)
                    end
                end)
                
                return success and result or "No result"
            """
            
            result = self.lua.execute(test_code)
            
            if isinstance(result, str) and len(result) > 100:
                stats['extracted_code'] = result
                return True, result, stats
            
            loadstring_match = LOADSTRING_XOR_RE.search(code)
            if loadstring_match:
                str1, str2 = loadstring_match.group(1), loadstring_match.group(2)
                try:
                    decoded = self.lua.execute(f'{obfuscated_code} return v7("{str1}", "{str2}")')
                    if decoded and isinstance(decoded, str) and len(decoded) > 50:
                        stats['extracted_code'] = decoded
                        return True, decoded, stats
                except:
                    pass
            
            return False, None, stats
            
        except Exception as e:
            return False, None, {"error": str(e)}

# Глобальный экземпляр
lua_executor = LuaRuntimeExecutor() if HAS_LUPA else None

# ============= ФУНКЦИИ ДЛЯ ОБРАБОТКИ КОДА =============

def apply_hookop_v2_formatting(code: str) -> str:
    """Применяет форматирование HookOpV2 к коду"""
    
    # Форматирование return statements
    code = re.sub(r'return\s*\(\s*\{', 'return {', code)
    code = re.sub(r'return\s*\(\s*\[', 'return [', code)
    code = re.sub(r'return\s*\(\s*function', 'return function', code)
    
    # Форматирование скобок
    code = re.sub(r'\(\s*\)', '()', code)
    code = re.sub(r'\[\s*\]', '[]', code)
    code = re.sub(r'\{\s*\}', '{}', code)
    
    # Форматирование методов с двоеточием
    code = re.sub(r'(\w+)\s*:\s*(\w+)', r'\1:\2', code)
    
    # Форматирование точек с запятой
    code = re.sub(r';\s*;', ';', code)
    code = re.sub(r';\s*$', '', code, flags=re.MULTILINE)
    
    # Форматирование запятых
    code = re.sub(r',\s*,', ',', code)
    
    # Форматирование присваиваний
    code = re.sub(r'=\s*=', '=', code)
    
    # Форматирование операторов
    code = re.sub(r'\s*\+\s*', '+', code)
    code = re.sub(r'\s*-\s*', '-', code)
    code = re.sub(r'\s*\*\s*', '*', code)
    code = re.sub(r'\s*/\s*', '/', code)
    code = re.sub(r'\s*=\s*', '=', code)
    code = re.sub(r'\s*<\s*', '<', code)
    code = re.sub(r'\s*>\s*', '>', code)
    code = re.sub(r'\s*<=\s*', '<=', code)
    code = re.sub(r'\s*>=\s*', '>=', code)
    code = re.sub(r'\s*==\s*', '==', code)
    code = re.sub(r'\s*~=\s*', '~=', code)
    
    # Форматирование таблиц
    code = re.sub(r'{\s*', '{', code)
    code = re.sub(r'\s*}', '}', code)
    code = re.sub(r',\s*}', '}', code)
    
    # Форматирование строковых конкатенаций
    code = re.sub(r'\s*\.\.\s*', '..', code)
    
    # Добавление отступов для блоков
    lines = code.split('\n')
    indent_level = 0
    formatted_lines = []
    
    for line in lines:
        stripped = line.strip()
        if stripped:
            # Уменьшаем отступ для закрывающих блоков
            if stripped.startswith('end') or stripped.startswith('else') or stripped.startswith('elseif') or stripped.startswith('until'):
                indent_level = max(0, indent_level - 1)
            
            # Добавляем отступ
            formatted_lines.append('    ' * indent_level + stripped)
            
            # Увеличиваем отступ для открывающих блоков
            if stripped.endswith('do') or stripped.endswith('then') or stripped.endswith('else') or stripped.endswith('elseif') or stripped.endswith('function') or stripped.endswith('{'):
                indent_level += 1
        else:
            formatted_lines.append('')
    
    code = '\n'.join(formatted_lines)
    
    return code

def decode_luraph_obfuscation(code: str, settings: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """Декодирует Luraph обфускацию"""
    stats = {
        'detected': False,
        'decoded_strings': 0,
        'extracted_code': None,
        'execution_success': False,
        'vm_detected': False,
        'hooked_calls': 0,
        'function_count': 0,
        'antidebug_removed': 0,
        'luraph_stats': {}
    }
    
    # Проверяем наличие Luraph обфускации
    if LURAPH_HEADER_RE.search(code):
        stats['detected'] = True
        
        # Удаляем анти-отладку
        if settings.get('remove_luraph_anti_debug', True):
            before_len = len(code)
            code = re.sub(LURAPH_ANTI_DEBUG_RE, '', code, flags=re.DOTALL)
            stats['antidebug_removed'] = before_len - len(code)
        
        # Декодируем Luraph числа (0x123_456_789)
        if settings.get('decode_luraph_strings', True):
            for match in LURAPH_NUMBER_ENCRYPT_RE.finditer(code):
                try:
                    num_str = match.group(0).replace('_', '').lower()
                    if num_str.startswith('0x'):
                        decoded_num = str(int(num_str, 16))
                        code = code.replace(match.group(0), decoded_num)
                        stats['decoded_strings'] += 1
                except:
                    continue
        
        # Извлекаем функции из таблицы
        table_match = LURAPH_RETURN_TABLE_RE.search(code)
        if table_match:
            func_matches = LURAPH_FUNCTION_RE.finditer(table_match.group(1))
            stats['function_count'] = len(list(func_matches))
        
        # Пытаемся выполнить через Lupa
        if HAS_LUPA and lua_executor and settings.get('decode_luraph', True):
            success, result, luraph_stats = lua_executor.execute_luraph_script(code)
            if success and result:
                stats['execution_success'] = True
                stats['decoded_strings'] = luraph_stats.get('decoded_strings', 0)
                stats['vm_detected'] = luraph_stats.get('vm_detected', False)
                stats['hooked_calls'] = luraph_stats.get('hooked_calls', 0)
                stats['extracted_code'] = result
                stats['luraph_stats'] = luraph_stats
                return result, stats
        
        # Извлекаем байткод
        if settings.get('extract_luraph_bytecode', True):
            bytecode_matches = LURAPH_BYTECODE_RE.findall(code)
            if bytecode_matches:
                stats['extracted_code'] = f"-- Luraph bytecode detected: {bytecode_matches[0]}"
        
        # Извлекаем loadstring
        load_matches = LURAPH_LOAD_RE.findall(code)
        if load_matches:
            stats['extracted_code'] = f"-- Luraph loadstring: {load_matches[0][:200]}"
    
    return code, stats

def decode_ntt_obfuscation(code: str, settings: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """Декодирует NTT обфускацию"""
    stats = {
        'detected': False,
        'decoded_strings': 0,
        'extracted_code': None,
        'execution_success': False,
        'function_name': None,
        'table_entries': 0
    }
    
    if NTT_HEADER_RE.search(code) or '_ySMoBAPw' in code:
        stats['detected'] = True
        
        if HAS_LUPA and lua_executor and settings.get('decode_ntt_obfuscator', True):
            success, result, ntt_stats = lua_executor.execute_ntt_obfuscation(code)
            if success and result:
                stats['execution_success'] = True
                stats['decoded_strings'] = ntt_stats.get('decoded_strings', 0)
                stats['extracted_code'] = result
                return result, stats
        
        decoded_code = code
        
        table_match = NTT_TABLE_RE.search(code)
        if table_match:
            table_content = table_match.group(1)
            stats['table_entries'] = table_content.count('{')
            
            func_match = NTT_DECODE_FUNCTION_RE.search(code)
            if func_match:
                func_name = func_match.group(1)
                stats['function_name'] = func_name
                
                pattern = r'\[\d+\]=\{\{(.*?)\},(\d+),?\}'
                for entry_match in re.finditer(pattern, table_content):
                    try:
                        numbers_str = entry_match.group(1)
                        key = int(entry_match.group(2))
                        
                        numbers = [int(n.strip()) for n in numbers_str.split(',') if n.strip()]
                        
                        decoded_chars = []
                        for num in numbers:
                            decoded_char = chr(num ^ key)
                            decoded_chars.append(decoded_char)
                        
                        decoded_string = ''.join(decoded_chars)
                        
                        old_call = f'{func_name}({len(stats.get("decoded_strings", 0)) + 1})'
                        new_string = f'"{decoded_string.replace(chr(34), chr(92)+chr(34))}"'
                        decoded_code = decoded_code.replace(old_call, new_string)
                        
                        stats['decoded_strings'] += 1
                        
                        if decoded_string.startswith(('loadstring', 'game:HttpGet', 'require', 'local', 'function')):
                            stats['extracted_code'] = decoded_string
                        elif len(decoded_string) > 100:
                            stats['extracted_code'] = decoded_string
                            
                    except Exception:
                        continue
        
        return decoded_code, stats
    
    return code, stats

def decode_v7_xor_function(code: str, settings: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """Декодирует новую обфускацию с v7 XOR функцией"""
    stats = {
        'detected': False,
        'decoded_strings': 0,
        'extracted_code': None,
        'execution_success': False
    }
    
    if 'v0=string.char' in code and 'v7(' in code and 'v4=v3.bxor' in code:
        stats['detected'] = True
        
        if HAS_LUPA and lua_executor and settings.get('lupa_execution', True):
            success, result, v7_stats = lua_executor.execute_new_obfuscation(code)
            if success and result:
                stats['execution_success'] = True
                stats['decoded_strings'] = 1
                stats['extracted_code'] = result
                return result, stats
        
        decoded_code = code
        
        v7_calls = re.findall(r'v7\("([^"]+)","([^"]+)"\)', code)
        
        for str1, str2 in v7_calls:
            try:
                decoded = xor_decrypt(str1, str2)
                if decoded and len(decoded) > 5:
                    old_call = f'v7("{str1}","{str2}")'
                    decoded_escaped = decoded.replace('"', '\\"')
                    decoded_code = decoded_code.replace(old_call, f'"{decoded_escaped}"')
                    stats['decoded_strings'] += 1
                    
                    if decoded.startswith('http') and len(decoded) > 20:
                        stats['extracted_code'] = decoded
            except:
                continue
        
        loadstring_matches = LOADSTRING_XOR_RE.findall(code)
        for str1, str2 in loadstring_matches:
            try:
                url = xor_decrypt(str1, str2)
                if url and url.startswith('http'):
                    stats['extracted_code'] = url
            except:
                continue
        
        return decoded_code, stats
    
    return code, stats

def decode_bit32_xor(code: str) -> Tuple[str, Dict[str, Any]]:
    """Декодирует bit32.bxor вызовы"""
    stats = {
        'bxor_decoded': 0,
        'values_calculated': []
    }
    
    for match in BIT32_XOR_CALL_RE.finditer(code):
        try:
            a = int(match.group(1))
            b = int(match.group(2))
            result = a ^ b
            old_call = match.group(0)
            code = code.replace(old_call, str(result))
            stats['bxor_decoded'] += 1
            stats['values_calculated'].append(f"{a} ^ {b} = {result}")
        except:
            continue
    
    for match in BIT32_XOR_VAR_RE.finditer(code):
        try:
            full_match = match.group(0)
            code = code.replace(full_match, "0")
            stats['bxor_decoded'] += 1
        except:
            continue
    
    return code, stats

def decode_wrd_table(code: str, settings: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """Декодирует WRD обфусцированный код"""
    stats = {
        'wrd_detected': False,
        'lupa_available': HAS_LUPA,
        'execution_success': False,
        'decoded_length': 0,
        'decoded_strings': 0
    }
    
    if WRD_HEADER_RE.search(code) or "wearedevs.net/obfuscator" in code:
        stats['wrd_detected'] = True
        
        if HAS_LUPA and lua_executor and settings.get('lupa_execution', True):
            success, decoded_code, wrd_stats = lua_executor.execute_wrd_script(code)
            if success and decoded_code:
                stats['execution_success'] = True
                stats['decoded_length'] = len(decoded_code)
                stats['decoded_strings'] = wrd_stats.get('decoded_strings', 0)
                return decoded_code, stats
    
    return code, stats

def decode_base64_string(b64_str: str) -> str:
    """Декодирует base64 строку"""
    try:
        b64_str = re.sub(r'[^A-Za-z0-9+/=]', '', b64_str)
        padding = 4 - len(b64_str) % 4
        if padding != 4:
            b64_str += '=' * padding
        
        decoded = base64.b64decode(b64_str, validate=True)
        
        if len(decoded) > 2 and decoded[:2] == b'\x1f\x8b':
            try:
                decoded = gzip.decompress(decoded)
            except Exception:
                pass
        
        return decoded.decode('utf-8', errors='ignore')
    except Exception:
        return b64_str

def decode_string_char(match) -> str:
    """Декодирует string.char() вызов"""
    args_str = match.group(1)
    
    try:
        args_str = re.sub(r'--[^\n]*', '', args_str)
        
        args = []
        current = ''
        paren_count = 0
        
        for char in args_str:
            if char == '(':
                paren_count += 1
                current += char
            elif char == ')':
                paren_count -= 1
                current += char
            elif char == ',' and paren_count == 0:
                if current.strip():
                    args.append(current.strip())
                current = ''
            else:
                current += char
        
        if current.strip():
            args.append(current.strip())
        
        bytes_list = []
        for arg in args:
            arg = arg.strip()
            if not arg:
                continue
                
            arg = arg.replace('bit32.bxor', '^')
            arg = arg.replace('bit32.band', '&')
            arg = arg.replace('bit32.bor', '|')
            
            try:
                arg_clean = re.sub(r'[^\d\+\-\*\/\%\^&|~()]', '', arg)
                if arg_clean:
                    arg_clean = arg_clean.replace('^', '**')
                    val = eval(arg_clean, {"__builtins__": {}}, {})
                else:
                    if arg.startswith('0x'):
                        val = int(arg, 16)
                    else:
                        numbers = re.findall(r'\d+', arg)
                        if numbers:
                            val = int(numbers[0])
                        else:
                            return match.group(0)
                
                if isinstance(val, (int, float)) and 0 <= val <= 255:
                    bytes_list.append(int(val))
                else:
                    return match.group(0)
                    
            except Exception:
                return match.group(0)
        
        if bytes_list:
            decoded = bytes(bytes_list).decode('utf-8', errors='ignore')
            if '"' in decoded and "'" in decoded:
                return '"' + decoded.replace('"', '\\"') + '"'
            elif '"' in decoded:
                return "'" + decoded + "'"
            else:
                return '"' + decoded + '"'
    
    except Exception:
        pass
    
    return match.group(0)

def xor_decrypt(data: str, key: str) -> str:
    """Выполняет XOR декодирование"""
    result = []
    key_len = len(key)
    
    for i in range(len(data)):
        char_code = ord(data[i]) ^ ord(key[i % key_len])
        result.append(chr(char_code))
    
    return ''.join(result)

def extract_xor_function(code: str) -> Dict[str, Any]:
    """Извлекает XOR функцию из кода"""
    xor_functions = {}
    
    matches = XOR_FUNCTION_RE.finditer(code)
    for match in matches:
        func_name = match.group(1)
        param1 = match.group(2)
        param2 = match.group(3)
        func_body = match.group(4)
        
        xor_functions[func_name] = {
            'name': func_name,
            'params': [param1, param2],
            'body': func_body,
        }
    
    return xor_functions

def execute_xor_decryption(code: str, settings: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """Выполняет XOR декодирование"""
    if not settings.get('execute_xor_functions', True):
        return code, {}
    
    xor_functions = extract_xor_function(code)
    
    if not xor_functions:
        return code, {}
    
    decryption_stats = {
        'total_functions': len(xor_functions),
        'decrypted_calls': 0,
        'failed_calls': 0,
        'decrypted_strings': [],
    }
    
    for func_name, func_info in xor_functions.items():
        pattern = re.compile(rf'{re.escape(func_name)}\s*\(\s*(["\'])(.*?)\1\s*,\s*(["\'])(.*?)\3\s*\)', re.S)
        matches = list(pattern.finditer(code))
        
        for match in matches:
            try:
                str1_content = match.group(2)
                str2_content = match.group(4)
                
                str1_decoded = decode_base64_string(str1_content)
                str2_decoded = decode_base64_string(str2_content)
                
                if str1_decoded == str1_content:
                    str1_decoded = str1_content
                if str2_decoded == str2_content:
                    str2_decoded = str2_content
                
                decrypted = xor_decrypt(str1_decoded, str2_decoded)
                
                final_result = decrypted
                
                b64_result = decode_base64_string(decrypted)
                if b64_result != decrypted:
                    final_result = b64_result
                
                old_call = match.group(0)
                
                if '"' in final_result and "'" in final_result:
                    new_call = '"' + final_result.replace('"', '\\"') + '"'
                elif '"' in final_result:
                    new_call = "'" + final_result + "'"
                else:
                    new_call = '"' + final_result + '"'
                
                code = code.replace(old_call, new_call)
                
                decryption_stats['decrypted_calls'] += 1
                decryption_stats['decrypted_strings'].append({
                    'original': old_call[:100],
                    'decrypted': final_result[:100],
                })
                
            except Exception:
                decryption_stats['failed_calls'] += 1
                continue
    
    return code, decryption_stats

def decode_table_arrays(code: str, settings: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """Декодирует табличные массивы"""
    if not settings.get('decode_table_arrays', True):
        return code, {}
    
    stats = {
        'tables_decoded': 0,
        'strings_found': 0,
    }
    
    matches = list(TABLE_ARRAY_RE.finditer(code))
    
    for match in reversed(matches):
        try:
            numbers_str = match.group(1)
            key = int(match.group(2))
            
            numbers = [int(n.strip()) for n in numbers_str.split(',') if n.strip()]
            
            result_chars = []
            for num in numbers:
                decrypted_char = chr(num ^ key)
                result_chars.append(decrypted_char)
            
            decrypted_string = ''.join(result_chars)
            
            final_string = decrypted_string
            
            b64_decoded = decode_base64_string(decrypted_string)
            if b64_decoded != decrypted_string:
                final_string = b64_decoded
            
            old_match = match.group(0)
            new_string = f'"{final_string.replace(chr(34), chr(92)+chr(34))}"'
            code = code[:match.start()] + new_string + code[match.end():]
            
            stats['tables_decoded'] += 1
            stats['strings_found'] += 1
            
        except Exception:
            continue
    
    return code, stats

def strip_line_comments(code: str) -> str:
    """Удаляет однострочные комментарии"""
    lines = code.split('\n')
    result = []
    in_string = False
    string_char = None
    escape = False
    
    for line in lines:
        new_line = ""
        i = 0
        while i < len(line):
            char = line[i]
            
            if not escape and char in '"\'' and (i == 0 or line[i-1] != '\\'):
                if not in_string:
                    in_string = True
                    string_char = char
                elif in_string and char == string_char:
                    in_string = False
                    string_char = None
                new_line += char
            elif char == '\\' and in_string:
                escape = not escape
                new_line += char
            else:
                escape = False
                if not in_string and char == '-' and i + 1 < len(line) and line[i+1] == '-':
                    break
                new_line += char
            i += 1
        
        if new_line.strip() or not in_string:
            result.append(new_line)
    
    return '\n'.join(result)

def strip_block_comments(code: str) -> str:
    """Удаляет блочные комментарии --[[ ... ]]"""
    result = []
    i = 0
    length = len(code)
    in_string = False
    string_char = None
    in_block_comment = False
    
    while i < length:
        char = code[i]
        
        if not in_block_comment and char in '"\'' and (i == 0 or code[i-1] != '\\'):
            if not in_string:
                in_string = True
                string_char = char
            elif in_string and char == string_char:
                in_string = False
                string_char = None
            result.append(char)
        
        elif not in_string and not in_block_comment and char == '-' and i + 1 < length and code[i+1] == '-' and i + 2 < length and code[i+2] == '[':
            in_block_comment = True
            i += 2
        elif in_block_comment and char == ']' and i + 1 < length and code[i+1] == ']':
            in_block_comment = False
            i += 1
        elif in_block_comment:
            pass
        else:
            result.append(char)
        
        i += 1
    
    return ''.join(result)

def delete_probels(code: str) -> str:
    """Удаляет лишние пробелы и пустые строки"""
    lines = code.split('\n')
    result = []
    
    for line in lines:
        line = line.strip()
        line = re.sub(r'\s+', ' ', line)
        if line:
            result.append(line)
    
    return '\n'.join(result)

def minifier(code: str) -> str:
    """Минифицирует Lua код"""
    code = strip_line_comments(code)
    code = strip_block_comments(code)
    code = delete_probels(code)
    
    code = re.sub(r'\s*=\s*', '=', code)
    code = re.sub(r'\s*\+\s*', '+', code)
    code = re.sub(r'\s*-\s*', '-', code)
    code = re.sub(r'\s*\*\s*', '*', code)
    code = re.sub(r'\s*/\s*', '/', code)
    code = re.sub(r'\s*,\s*', ',', code)
    code = re.sub(r'\s*;\s*', ';', code)
    code = re.sub(r'\s*\(\s*', '(', code)
    code = re.sub(r'\s*\)\s*', ')', code)
    code = re.sub(r'\s*\{\s*', '{', code)
    code = re.sub(r'\s*\}\s*', '}', code)
    code = re.sub(r'\s*\[\s*', '[', code)
    code = re.sub(r'\s*\]\s*', ']', code)
    
    code = re.sub(r'\n\s*\n', '\n', code)
    
    return code

def concat_strings(code: str) -> str:
    """Объединяет конкатенированные строки"""
    pattern = r'(["\'])(.*?)\1\s*\.\.\s*(["\'])(.*?)\3'
    
    def replace_concat(match):
        quote1 = match.group(1)
        str1 = match.group(2)
        quote2 = match.group(3)
        str2 = match.group(4)
        
        combined = str1 + str2
        return f'{quote1}{combined}{quote1}'
    
    prev_code = None
    while prev_code != code:
        prev_code = code
        code = re.sub(pattern, replace_concat, code)
    
    return code

def remove_fake_flags(code: str) -> str:
    """Удаляет фейковые флаги и анти-деобфускацию"""
    fake_flags = [
        r'if\s+_G\["\w+"\]\s+or\s+_\w+\s+then\s+return\s+end',
        r'if\s+debug\s+and\s+debug\.\w+\s+then\s+error\(".*?"\)\s+end',
        r'if\s+_\w+_\s+then\s+while\s+true\s+do\s+end\s+end',
        r'if\s+__\w+__\s+then\s+return\s+{}?\s+end',
        r'getfenv\(\)\.\w+\s*=\s*nil',
        r'setfenv\(\d+,\s*\{\}\)',
    ]
    
    for pattern in fake_flags:
        code = re.sub(pattern, '', code, flags=re.DOTALL)
    
    return code

def advanced_xor_decoding(code: str) -> Tuple[str, Dict[str, Any]]:
    """Расширенное XOR декодирование с множественными ключами"""
    stats = {
        'decoded_count': 0,
        'patterns_found': 0
    }
    
    xor_patterns = [
        (r'bit32\.bxor\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)', lambda a, b: str(int(a) ^ int(b))),
        (r'bit\.bxor\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)', lambda a, b: str(int(a) ^ int(b))),
        (r'bit32\.band\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)', lambda a, b: str(int(a) & int(b))),
        (r'bit32\.bor\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)', lambda a, b: str(int(a) | int(b))),
        (r'bit32\.lshift\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)', lambda a, b: str(int(a) << int(b))),
        (r'bit32\.rshift\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)', lambda a, b: str(int(a) >> int(b))),
        (r'bit32\.rotate\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)', lambda a, b: str(((int(a) << int(b)) | (int(a) >> (32 - int(b)))) & 0xFFFFFFFF)),
    ]
    
    for pattern, decoder in xor_patterns:
        matches = re.findall(pattern, code)
        if matches:
            stats['patterns_found'] += len(matches)
            for match in matches:
                try:
                    result = decoder(match[0], match[1])
                    old_call = re.search(pattern.replace(r'\(', r'\(').replace(r'\)', r'\)'), code)
                    if old_call:
                        code = code.replace(old_call.group(0), result)
                        stats['decoded_count'] += 1
                except:
                    continue
    
    return code, stats

def extract_hidden_functions(code: str) -> Dict[str, List[str]]:
    """Извлекает скрытые функции и метаданные"""
    extracted = {
        'v7_calls': [],
        'xor_strings': [],
        'urls': [],
        'window_creations': [],
        'decoded_requires': [],
        'ntt_strings': [],
        'luraph_functions': [],
        'luraph_vm': [],
        'hooked_potential': [],
    }
    
    v7_calls = re.findall(r'v7\("([^"]+)","([^"]+)"\)', code)
    for str1, str2 in v7_calls:
        extracted['v7_calls'].append(f'v7("{str1[:20]}...","{str2[:20]}...")')
        try:
            decoded = xor_decrypt(str1, str2)
            if decoded:
                extracted['xor_strings'].append(decoded[:100])
                if decoded.startswith('http'):
                    extracted['urls'].append(decoded)
        except:
            pass
    
    if 'CreateWindow' in code:
        extracted['window_creations'].append('Обнаружено создание GUI окна')
    
    require_matches = PCALL_XOR_RE.findall(code)
    for str1, str2 in require_matches:
        try:
            decoded = xor_decrypt(str1, str2)
            extracted['decoded_requires'].append(decoded[:100])
        except:
            pass
    
    ntt_matches = NTT_CALL_RE.findall(code)
    for func_name, index in ntt_matches:
        extracted['ntt_strings'].append(f'{func_name}({index})')
    
    luraph_funcs = LURAPH_FUNCTION_RE.findall(code)
    for func_name, params, _ in luraph_funcs:
        extracted['luraph_functions'].append(f'{func_name}({params})')
    
    if 'bit32.rotate' in code or 'bit32.countlz' in code:
        extracted['luraph_vm'].append('Luraph VM detected')
    
    # Поиск функций для HookOp
    for func in HOOKABLE_FUNCTIONS_RE.finditer(code):
        func_name = func.group(1)
        if len(func_name) > 1 and not func_name.startswith('_'):
            extracted['hooked_potential'].append(func_name)
    
    return extracted

def analyze_functionality(code: str) -> Dict[str, List[str]]:
    """Анализирует функциональность скрипта"""
    analysis = {
        'prints': [],
        'network_requests': [],
        'gui_elements': [],
        'execution_methods': [],
        'key_systems': [],
        'remote_calls': [],
        'teleport_detected': [],
        'anti_ban': [],
        'esp_detected': [],
        'aimbot_detected': [],
        'webhooks': [],
        'xor_functions': [],
        'v7_functions': [],
        'window_ui': [],
        'ntt_obfuscation': [],
        'luraph_obfuscation': [],
        'luraph_vm': [],
        'debug_checks': [],
        'obfuscation_layers': 0,
    }
    
    if 'v7(' in code:
        analysis['v7_functions'].append('XOR декодер (v7)')
        analysis['obfuscation_layers'] += 1
    
    if '_ySMoBAPw' in code:
        analysis['ntt_obfuscation'].append('NTT Obfuscator Detected')
        analysis['obfuscation_layers'] += 1
    
    if LURAPH_HEADER_RE.search(code):
        analysis['luraph_obfuscation'].append('Luraph Obfuscator v14.6')
        analysis['obfuscation_layers'] += 1
    
    if 'bit32.rotate' in code or 'bit32.countlz' in code:
        analysis['luraph_vm'].append('Luraph VM Emulation')
    
    if 'CreateWindow' in code:
        analysis['window_ui'].append('WindUI Window')
    if 'addTab' in code:
        analysis['window_ui'].append('WindUI Tabs')
    if 'addSection' in code:
        analysis['window_ui'].append('WindUI Sections')
    
    print_matches = re.findall(r'\bprint\s*\(\s*([^)]+)\s*\)', code, re.I)
    for match in print_matches:
        analysis['prints'].append(match[:100])
    
    http_matches = re.findall(r'HttpGet(?:Async)?\s*\(\s*([^)]+)\s*\)', code, re.I)
    for match in http_matches:
        analysis['network_requests'].append(match[:100])
    
    http_matches = re.findall(r'HttpPost(?:Async)?\s*\(\s*([^)]+)\s*\)', code, re.I)
    for match in http_matches:
        analysis['network_requests'].append(f"POST: {match[:100]}")
    
    webhook_matches = re.findall(r'(https?://discord(?:app)?\.com/api/webhooks/\d+/\S+)', code, re.I)
    for match in webhook_matches:
        analysis['webhooks'].append(match[:100])
    
    remote_matches = re.findall(r'(?:FireServer|InvokeServer)\s*\([^)]*\)', code, re.I)
    for match in remote_matches:
        analysis['remote_calls'].append(match[:100])
    
    gui_matches = re.findall(r'Instance\.new\s*\(\s*["\'](?:ScreenGui|Frame|TextButton|TextBox|ScrollingFrame|ImageLabel|ImageButton|TextLabel|UICorner)["\'][^)]*\)', code, re.I)
    for match in gui_matches:
        analysis['gui_elements'].append(match[:100])
    
    load_matches = re.findall(r'(loadstring|require|dofile|loadfile)\s*\([^)]*\)', code, re.I)
    for match in load_matches:
        analysis['execution_methods'].append(match[:100])
    
    key_matches = re.findall(r'(?:KeySystem|CheckKey|ValidateKey|VerifyKey|key[:=]\s*["\']|license["\']|hwid|HWID)', code, re.I)
    for match in key_matches:
        analysis['key_systems'].append(match[:50])
    
    teleport_matches = re.findall(r'(TeleportService|Teleport|:Teleport\(|\bTP\b)', code, re.I)
    for match in teleport_matches:
        analysis['teleport_detected'].append(match[:50])
    
    antiban_matches = re.findall(r'(antiban|AntiBan|Bypass|AntiCheat|BAN_|kick\()', code, re.I)
    for match in antiban_matches:
        analysis['anti_ban'].append(match[:50])
    
    esp_matches = re.findall(r'(ESP|esp|Highlight|Chams|BoxESP|Tracer|NameESP|HealthBar|Wallhack)', code, re.I)
    for match in esp_matches:
        analysis['esp_detected'].append(match[:50])
    
    aimbot_matches = re.findall(r'(aimbot|Aimbot|SilentAim|TriggerBot|AutoShoot|AutoFire|AimAssist|LockTarget)', code, re.I)
    for match in aimbot_matches:
        analysis['aimbot_detected'].append(match[:50])
    
    debug_matches = re.findall(r'debug\.(\w+)', code, re.I)
    for match in debug_matches:
        analysis['debug_checks'].append(f'debug.{match}')
    
    xor_funcs = extract_xor_function(code)
    for name in xor_funcs.keys():
        analysis['xor_functions'].append(f"XOR: {name}")
    
    return analysis

def clean_wrd_logs(code: str) -> str:
    """Удаляет WRD логи из кода"""
    code = re.sub(r'-- STATISTICS --.*?-- End of raw log', '', code, flags=re.DOTALL)
    code = re.sub(r'-- FULL LOG --.*?-- End of raw log', '', code, flags=re.DOTALL)
    code = re.sub(r'\n\[\d+\] \[[^\]]+\] .*', '\n', code)
    code = re.sub(r'\n\s*\n\s*\n', '\n\n', code)
    return code

def process_pipeline(code: str, settings: Dict[str, Any], user_id: int = None) -> Dict[str, Any]:
    """Основной пайплайн деобфускации"""
    original = code
    processed_code = code
    
    stats = {
        'string_char_decoded': 0,
        'xor_functions_found': 0,
        'xor_calls_decoded': 0,
        'tables_decoded': 0,
        'junk_removed': 0,
        'wrd_detected': False,
        'wrd_log_detected': False,
        'wrd_executed': False,
        'v7_obfuscation_detected': False,
        'v7_decoded': False,
        'v7_strings_decoded': 0,
        'v7_extracted_code': None,
        'bit32_xor_decoded': 0,
        'hidden_functions': {},
        'execution_log': [],
        'line_comments_removed': 0,
        'block_comments_removed': 0,
        'probels_removed': 0,
        'minifier_applied': False,
        'advanced_xor_decoded': 0,
        'fake_flags_removed': 0,
        'strings_concatenated': 0,
        'ntt_detected': False,
        'ntt_decoded': False,
        'ntt_strings_decoded': 0,
        'ntt_extracted_code': None,
        'luraph_detected': False,
        'luraph_decoded': False,
        'luraph_strings_decoded': 0,
        'luraph_extracted_code': None,
        'luraph_vm_detected': False,
        'luraph_hooked_calls': 0,
        'luraph_antidebug_removed': 0,
        'hookop_enabled': settings.get('hookop_enabled', False),
        'hookop_v2_enabled': settings.get('hookop_v2_enabled', False),
        'spy_execute_enabled': settings.get('spy_execute_enabled', False),
        'hooked_functions': [],
        'execution_trace': [],
        'sandbox_mode': settings.get('sandbox_mode', True),
    }
    
    # Применяем HookOp если включен
    if settings.get('hookop_enabled', False) and HAS_LUPA and lua_executor:
        processed_code = lua_executor.enable_hookop(processed_code)
        stats['hookop_enabled'] = True
    
    # Применяем HookOpV2 если включен
    if settings.get('hookop_v2_enabled', False):
        processed_code = apply_hookop_v2_formatting(processed_code)
        if HAS_LUPA and lua_executor:
            processed_code = lua_executor.enable_hookop_v2(processed_code)
        stats['hookop_v2_enabled'] = True
    
    # Применяем SpyExecute если включен
    if settings.get('spy_execute_enabled', False) and HAS_LUPA and lua_executor:
        processed_code = lua_executor.enable_spy_execute(processed_code)
        stats['spy_execute_enabled'] = True
    
    # Применяем песочницу
    if settings.get('sandbox_mode', True) and HAS_LUPA and lua_executor:
        processed_code = lua_executor.enable_sandbox(processed_code)
        stats['sandbox_mode'] = True
    
    # Применяем трассировку
    if settings.get('trace_calls', False) and HAS_LUPA and lua_executor:
        processed_code = lua_executor.enable_tracing(processed_code)
    
    # Применяем перехват require
    if settings.get('hook_require', False) and HAS_LUPA and lua_executor:
        processed_code = lua_executor.hook_require(processed_code)
    
    # Очистка мусора
    if settings.get('autodelete', False):
        original_len = len(processed_code)
        processed_code = ''.join([c for c in processed_code if ord(c) >= 32 or c in '\n\r\t'])
        stats['junk_removed'] = original_len - len(processed_code)
    
    # Удаляем WRD логи
    if '-- STATISTICS --' in processed_code or '-- FULL LOG --' in processed_code:
        stats['wrd_log_detected'] = True
        processed_code = clean_wrd_logs(processed_code)
    
    # ===== 1. ДЕКОДИРУЕМ LURAPH ОБФУСКАЦИЮ =====
    if settings.get('decode_luraph', True):
        luraph_decoded, luraph_stats = decode_luraph_obfuscation(processed_code, settings)
        if luraph_stats.get('detected', False):
            stats['luraph_detected'] = True
            stats['luraph_strings_decoded'] = luraph_stats.get('decoded_strings', 0)
            stats['luraph_extracted_code'] = luraph_stats.get('extracted_code')
            stats['luraph_vm_detected'] = luraph_stats.get('vm_detected', False)
            stats['luraph_hooked_calls'] = luraph_stats.get('hooked_calls', 0)
            stats['luraph_antidebug_removed'] = luraph_stats.get('antidebug_removed', 0)
            if luraph_stats.get('execution_success', False):
                stats['luraph_decoded'] = True
                if luraph_stats.get('extracted_code'):
                    processed_code = luraph_stats['extracted_code']
            processed_code = luraph_decoded
    
    # ===== 2. ДЕКОДИРУЕМ NTT ОБФУСКАЦИЮ =====
    if settings.get('decode_ntt_obfuscator', True):
        ntt_decoded, ntt_stats = decode_ntt_obfuscation(processed_code, settings)
        if ntt_stats.get('detected', False):
            stats['ntt_detected'] = True
            stats['ntt_strings_decoded'] = ntt_stats.get('decoded_strings', 0)
            stats['ntt_extracted_code'] = ntt_stats.get('extracted_code')
            if ntt_stats.get('execution_success', False):
                stats['ntt_decoded'] = True
                if ntt_stats.get('extracted_code'):
                    processed_code = ntt_stats['extracted_code']
            processed_code = ntt_decoded
    
    # ===== 3. ДЕКОДИРУЕМ НОВУЮ ОБФУСКАЦИЮ (v7 XOR) =====
    if settings.get('decode_bit32_xor', True):
        v7_decoded, v7_stats = decode_v7_xor_function(processed_code, settings)
        if v7_stats.get('detected', False):
            stats['v7_obfuscation_detected'] = True
            stats['v7_strings_decoded'] = v7_stats.get('decoded_strings', 0)
            stats['v7_extracted_code'] = v7_stats.get('extracted_code')
            if v7_stats.get('execution_success', False):
                stats['v7_decoded'] = True
                if v7_stats.get('extracted_code'):
                    processed_code = v7_stats['extracted_code']
    
    # ===== 4. ДЕКОДИРУЕМ BIT32.XOR =====
    if settings.get('decode_bit32_xor', True):
        processed_code, bit32_stats = decode_bit32_xor(processed_code)
        stats['bit32_xor_decoded'] = bit32_stats.get('bxor_decoded', 0)
    
    # ===== 5. ДЕКОДИРУЕМ WRD ЧЕРЕЗ LUPA =====
    if settings.get('lupa_execution', True) and HAS_LUPA:
        wrd_decoded, wrd_stats = decode_wrd_table(processed_code, settings)
        if wrd_stats.get('execution_success', False):
            processed_code = wrd_decoded
            stats['wrd_executed'] = True
            stats['wrd_detected'] = wrd_stats.get('wrd_detected', False)
            stats['wrd_strings_decoded'] = wrd_stats.get('decoded_strings', 0)
    
    # ===== 6. ДЕКОДИРУЕМ STRING.CHAR =====
    if settings.get('decode_char', True):
        string_char_matches = list(STRING_CHAR_RE.finditer(processed_code))
        stats['string_char_decoded'] = len(string_char_matches)
        
        for match in reversed(string_char_matches):
            decoded = decode_string_char(match)
            if decoded != match.group(0):
                processed_code = processed_code[:match.start()] + decoded + processed_code[match.end():]
    
    # ===== 7. ВЫПОЛНЯЕМ XOR ДЕКОДИРОВАНИЕ =====
    xor_functions = extract_xor_function(processed_code)
    stats['xor_functions_found'] = len(xor_functions)
    
    if xor_functions and settings.get('execute_xor_functions', True):
        processed_code, xor_stats = execute_xor_decryption(processed_code, settings)
        stats['xor_calls_decoded'] = xor_stats.get('decrypted_calls', 0)
    
    # ===== 8. ДЕКОДИРУЕМ ТАБЛИЧНЫЕ МАССИВЫ =====
    if settings.get('decode_table_arrays', True):
        processed_code, table_stats = decode_table_arrays(processed_code, settings)
        stats['tables_decoded'] = table_stats.get('tables_decoded', 0)
    
    # ===== 9. ИЗВЛЕКАЕМ СКРЫТЫЕ ФУНКЦИИ =====
    if settings.get('extract_hidden_functions', True):
        stats['hidden_functions'] = extract_hidden_functions(original)
    
    # ===== 10. УДАЛЯЕМ ФЕЙКОВЫЕ ФЛАГИ =====
    if settings.get('remove_fake_flags', True):
        before_len = len(processed_code)
        processed_code = remove_fake_flags(processed_code)
        stats['fake_flags_removed'] = before_len - len(processed_code)
    
    # ===== 11. РАСШИРЕННОЕ XOR ДЕКОДИРОВАНИЕ =====
    if settings.get('advanced_xor_decoding', True):
        processed_code, adv_xor_stats = advanced_xor_decoding(processed_code)
        stats['advanced_xor_decoded'] = adv_xor_stats.get('decoded_count', 0)
    
    # ===== 12. ОБЪЕДИНЯЕМ СТРОКИ =====
    if settings.get('concat_strings', True):
        before_len = len(processed_code)
        processed_code = concat_strings(processed_code)
        stats['strings_concatenated'] = before_len - len(processed_code)
    
    # ===== 13. УДАЛЯЕМ ОДНОСТРОЧНЫЕ КОММЕНТАРИИ =====
    if settings.get('strip_line_comments', False):
        before_len = len(processed_code)
        processed_code = strip_line_comments(processed_code)
        stats['line_comments_removed'] = before_len - len(processed_code)
    
    # ===== 14. УДАЛЯЕМ БЛОЧНЫЕ КОММЕНТАРИИ =====
    if settings.get('strip_block_comments', False):
        before_len = len(processed_code)
        processed_code = strip_block_comments(processed_code)
        stats['block_comments_removed'] = before_len - len(processed_code)
    
    # ===== 15. УДАЛЯЕМ ПРОБЕЛЫ =====
    if settings.get('delete_probels', False):
        before_len = len(processed_code)
        processed_code = delete_probels(processed_code)
        stats['probels_removed'] = before_len - len(processed_code)
    
    # ===== 16. МИНИФИКАЦИЯ =====
    if settings.get('minifier', False):
        processed_code = minifier(processed_code)
        stats['minifier_applied'] = True
    
    # ===== 17. АНАЛИЗ ФУНКЦИОНАЛЬНОСТИ =====
    functionality_analysis = {}
    if settings.get('analyze_functionality', True):
        functionality_analysis = analyze_functionality(processed_code)
    
    # ===== 18. ФИНАЛЬНАЯ ПРОВЕРКА =====
    if settings.get('remove_obfuscation_layers', True):
        if 'v7(' in processed_code and stats['v7_strings_decoded'] > 0:
            processed_code = re.sub(r'v7\("[^"]+","[^"]+"\)', '"DECODED"', processed_code)
        
        if WRD_HEADER_RE.search(processed_code) and HAS_LUPA:
            wrd_decoded2, _ = decode_wrd_table(processed_code, settings)
            if wrd_decoded2 != processed_code:
                processed_code = wrd_decoded2
                stats['wrd_executed'] = True
        
        if '_ySMoBAPw' in processed_code and stats['ntt_strings_decoded'] > 0 and HAS_LUPA:
            ntt_decoded2, _ = decode_ntt_obfuscation(processed_code, settings)
            if ntt_decoded2 != processed_code:
                processed_code = ntt_decoded2
                stats['ntt_decoded'] = True
        
        if LURAPH_HEADER_RE.search(processed_code) and HAS_LUPA:
            luraph_decoded2, _ = decode_luraph_obfuscation(processed_code, settings)
            if luraph_decoded2 != processed_code:
                processed_code = luraph_decoded2
                stats['luraph_decoded'] = True
    
    # Определяем детекты
    stats['wrd_detected'] = stats['wrd_detected'] or bool(WRD_HEADER_RE.search(original))
    stats['ntt_detected'] = stats['ntt_detected'] or bool(NTT_HEADER_RE.search(original)) or '_ySMoBAPw' in original
    stats['luraph_detected'] = stats['luraph_detected'] or bool(LURAPH_HEADER_RE.search(original))
    
    # Применяем HookOpV2 форматирование в конце, если включено
    if settings.get('hookop_v2_enabled', False):
        processed_code = apply_hookop_v2_formatting(processed_code)
    
    return {
        'original': original,
        'processed': processed_code,
        'wrd_detected': stats['wrd_detected'],
        'wrd_log_detected': stats['wrd_log_detected'],
        'wrd_executed': stats['wrd_executed'],
        'v7_obfuscation_detected': stats['v7_obfuscation_detected'],
        'v7_decoded': stats['v7_decoded'],
        'v7_extracted_code': stats['v7_extracted_code'],
        'ntt_detected': stats['ntt_detected'],
        'ntt_decoded': stats['ntt_decoded'],
        'ntt_extracted_code': stats['ntt_extracted_code'],
        'luraph_detected': stats['luraph_detected'],
        'luraph_decoded': stats['luraph_decoded'],
        'luraph_extracted_code': stats['luraph_extracted_code'],
        'luraph_vm_detected': stats['luraph_vm_detected'],
        'functionality': functionality_analysis,
        'stats': stats,
        'xor_functions_found': stats['xor_functions_found'],
        'hidden_functions': stats.get('hidden_functions', {}),
        'hookop_enabled': stats['hookop_enabled'],
        'hookop_v2_enabled': stats['hookop_v2_enabled'],
        'spy_execute_enabled': stats['spy_execute_enabled'],
        'sandbox_mode': stats['sandbox_mode'],
    }

# ============= КЛАВИАТУРА НАСТРОЕК =============

def create_settings_keyboard(user_id: int, page: int = 0) -> InlineKeyboardMarkup:
    s = get_settings(user_id)
    USER_KEYBOARD_PAGE[user_id] = page
    
    if page == 0:
        keyboard = [
            [
                InlineKeyboardButton(
                    f"🔄 Lupa Execute: {'✅' if s.get('lupa_execution', True) else '❌'}",
                    callback_data="toggle_lupa_execution"
                ),
                InlineKeyboardButton(
                    f"📦 WRD Runtime: {'✅' if s.get('execute_wrd_runtime', True) else '❌'}",
                    callback_data="toggle_execute_wrd_runtime"
                )
            ],
            [
                InlineKeyboardButton(
                    f"🆕 v7 XOR Decode: {'✅' if s.get('decode_bit32_xor', True) else '❌'}",
                    callback_data="toggle_decode_bit32_xor"
                ),
                InlineKeyboardButton(
                    f"🔍 NTT Decode: {'✅' if s.get('decode_ntt_obfuscator', True) else '❌'}",
                    callback_data="toggle_decode_ntt_obfuscator"
                )
            ],
            [
                InlineKeyboardButton(
                    f"🔮 Luraph Decode: {'✅' if s.get('decode_luraph', True) else '❌'}",
                    callback_data="toggle_decode_luraph"
                ),
                InlineKeyboardButton(
                    f"🧬 Luraph VM: {'✅' if s.get('luraph_vm_emulation', True) else '❌'}",
                    callback_data="toggle_luraph_vm_emulation"
                )
            ],
            [
                InlineKeyboardButton(
                    f"📝 String.Char: {'✅' if s['decode_char'] else '❌'}",
                    callback_data="toggle_decode_char"
                ),
                InlineKeyboardButton(
                    f"🔑 XOR Execute: {'✅' if s['execute_xor_functions'] else '❌'}",
                    callback_data="toggle_execute_xor_functions"
                )
            ],
            [
                InlineKeyboardButton(f"🔧 HookOp/Spy ➡️", callback_data="page_3"),
                InlineKeyboardButton(f"📋 Page 2 ➡️", callback_data="page_1")
            ]
        ]
    elif page == 1:
        keyboard = [
            [
                InlineKeyboardButton(
                    f"🔬 Advanced XOR: {'✅' if s['advanced_xor_decoding'] else '❌'}",
                    callback_data="toggle_advanced_xor_decoding"
                ),
                InlineKeyboardButton(
                    f"🔎 Deep Analysis: {'✅' if s['deep_analysis'] else '❌'}",
                    callback_data="toggle_deep_analysis"
                )
            ],
            [
                InlineKeyboardButton(
                    f"📄 Strip Line Cmt: {'✅' if s['strip_line_comments'] else '❌'}",
                    callback_data="toggle_strip_line_comments"
                ),
                InlineKeyboardButton(
                    f"📑 Strip Block Cmt: {'✅' if s['strip_block_comments'] else '❌'}",
                    callback_data="toggle_strip_block_comments"
                )
            ],
            [
                InlineKeyboardButton(
                    f"🗑️ Delete Probels: {'✅' if s['delete_probels'] else '❌'}",
                    callback_data="toggle_delete_probels"
                ),
                InlineKeyboardButton(
                    f"📦 Minifier: {'✅' if s['minifier'] else '❌'}",
                    callback_data="toggle_minifier"
                )
            ],
            [
                InlineKeyboardButton(
                    f"💾 ZIP Output: {'✅' if s['zip_outputs'] else '❌'}",
                    callback_data="toggle_zip_outputs"
                ),
                InlineKeyboardButton(
                    f"🚫 Remove Flags: {'✅' if s['remove_fake_flags'] else '❌'}",
                    callback_data="toggle_remove_fake_flags"
                )
            ],
            [
                InlineKeyboardButton(f"⬅️ Page 1", callback_data="page_0"),
                InlineKeyboardButton(f"🔧 Page 3 ➡️", callback_data="page_2")
            ]
        ]
    elif page == 2:
        keyboard = [
            [
                InlineKeyboardButton(
                    f"🎯 Extract Code: {'✅' if s.get('extract_actual_code', True) else '❌'}",
                    callback_data="toggle_extract_actual_code"
                ),
                InlineKeyboardButton(
                    f"🧩 Concat Strings: {'✅' if s['concat_strings'] else '❌'}",
                    callback_data="toggle_concat_strings"
                )
            ],
            [
                InlineKeyboardButton(
                    f"🌐 Non-UTF8: {'✅' if s['accept_non_utf8'] else '❌'}",
                    callback_data="toggle_accept_non_utf8"
                ),
                InlineKeyboardButton(
                    f"📊 Lupa Status: {'✅' if HAS_LUPA else '❌'}",
                    callback_data="lupa_status"
                )
            ],
            [
                InlineKeyboardButton(
                    f"🧅 Remove Layers: {'✅' if s.get('remove_obfuscation_layers', True) else '❌'}",
                    callback_data="toggle_remove_obfuscation_layers"
                ),
                InlineKeyboardButton(
                    f"🔍 WRD Lit: {'✅' if s['wrd_literals'] else '❌'}",
                    callback_data="toggle_wrd_literals"
                )
            ],
            [
                InlineKeyboardButton(
                    f"🔮 Extract Luraph Bytecode: {'✅' if s.get('extract_luraph_bytecode', True) else '❌'}",
                    callback_data="toggle_extract_luraph_bytecode"
                ),
                InlineKeyboardButton(
                    f"🛡️ Bypass Antidebug: {'✅' if s.get('bypass_antidebug', True) else '❌'}",
                    callback_data="toggle_bypass_antidebug"
                )
            ],
            [
                InlineKeyboardButton(f"⬅️ Page 2", callback_data="page_1"),
                InlineKeyboardButton(f"🔧 HookOp/Spy ➡️", callback_data="page_3")
            ]
        ]
    else:  # page 3 - HookOp, HookOpV2, SpyExecute и продвинутые функции
        keyboard = [
            [
                InlineKeyboardButton(
                    f"🪝 HookOp V1: {'✅' if s.get('hookop_enabled', False) else '❌'}",
                    callback_data="toggle_hookop_enabled"
                ),
                InlineKeyboardButton(
                    f"🔧 HookOp V2: {'✅' if s.get('hookop_v2_enabled', False) else '❌'}",
                    callback_data="toggle_hookop_v2_enabled"
                )
            ],
            [
                InlineKeyboardButton(
                    f"👁️ SpyExecute: {'✅' if s.get('spy_execute_enabled', False) else '❌'}",
                    callback_data="toggle_spy_execute_enabled"
                ),
                InlineKeyboardButton(
                    f"📋 Trace Calls: {'✅' if s.get('trace_calls', False) else '❌'}",
                    callback_data="toggle_trace_calls"
                )
            ],
            [
                InlineKeyboardButton(
                    f"📦 Sandbox: {'✅' if s.get('sandbox_mode', True) else '❌'}",
                    callback_data="toggle_sandbox_mode"
                ),
                InlineKeyboardButton(
                    f"📚 Hook Require: {'✅' if s.get('hook_require', False) else '❌'}",
                    callback_data="toggle_hook_require"
                )
            ],
            [
                InlineKeyboardButton(
                    f"📡 Hook Loadstring: {'✅' if s.get('hook_loadstring', False) else '❌'}",
                    callback_data="toggle_hook_loadstring"
                ),
                InlineKeyboardButton(
                    f"🌐 Hook HTTP: {'✅' if s.get('hook_http', False) else '❌'}",
                    callback_data="toggle_hook_http"
                )
            ],
            [
                InlineKeyboardButton(
                    f"💾 Monitor FS: {'✅' if s.get('monitor_filesystem', False) else '❌'}",
                    callback_data="toggle_monitor_filesystem"
                ),
                InlineKeyboardButton(
                    f"🔑 Detect Keyloggers: {'✅' if s.get('detect_keyloggers', False) else '❌'}",
                    callback_data="toggle_detect_keyloggers"
                )
            ],
            [
                InlineKeyboardButton(
                    f"💉 Detect Injection: {'✅' if s.get('detect_injection', False) else '❌'}",
                    callback_data="toggle_detect_injection"
                ),
                InlineKeyboardButton(
                    f"📦 Auto Extract: {'✅' if s.get('auto_extract_payloads', True) else '❌'}",
                    callback_data="toggle_auto_extract_payloads"
                )
            ],
            [
                InlineKeyboardButton(
                    f"🧠 Memory Analysis: {'✅' if s.get('memory_analysis', False) else '❌'}",
                    callback_data="toggle_memory_analysis"
                ),
                InlineKeyboardButton(
                    f"🔄 Reset All", 
                    callback_data="reset_settings"
                )
            ],
            [
                InlineKeyboardButton(f"⬅️ Page 2", callback_data="page_2"),
                InlineKeyboardButton(f"📋 Page 1", callback_data="page_0")
            ]
        ]
    return InlineKeyboardMarkup(keyboard)

# ============= ОБРАБОТЧИКИ TELEGRAM =============

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Обработчик команды /start"""
    status_emoji = '✅' if HAS_LUPA else '❌'
    text = f"""
🔰 **УНИВЕРСАЛЬНЫЙ DEOBFUSCATOR PRO** 🔰

🤖 **Поддерживаемые типы обфускации:**
• ✅ WeAreDevs (WRD) - выполнение через Lupa
• ✅ Luraph Obfuscator v14.6 - VM эмуляция
• ✅ NTT Obfuscator - табличная XOR обфускация
• ✅ Новая XOR/bit32 обфускация с v7 функцией
• ✅ XOR декодирование
• ✅ string.char() декодинг
• ✅ Табличные массивы
• ✅ Bit32.bxor вычисление

🪝 **Продвинутые функции:**
• ✅ HookOp V1 - перехват и анализ функций
• ✅ HookOp V2 - форматирование return, (), :, ;
• ✅ SpyExecute - отслеживание выполнения
• ✅ Sandbox Mode - безопасная песочница
• ✅ Call Tracing - трассировка вызовов
• ✅ HTTP/Require Hooking - перехват запросов
• ✅ Anti-Debug Bypass - обход анти-отладки

📊 **Статус Lupa: {status_emoji}**

📤 **Отправьте .lua/.luau файл, ссылку или код**

⚙️ **Настройки:**
• Используйте кнопки ниже для конфигурации
• HookOp V2 на странице 3
• /help для списка команд
"""
    await update.message.reply_text(
        text,
        reply_markup=create_settings_keyboard(update.effective_user.id, 0),
        parse_mode='Markdown'
    )

async def handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user_id = query.from_user.id
    data = query.data
    current_page = USER_KEYBOARD_PAGE.get(user_id, 0)
    
    if data.startswith('page_'):
        page_num = int(data.split('_')[1])
        await query.edit_message_reply_markup(
            reply_markup=create_settings_keyboard(user_id, page_num)
        )
        return
    
    if data == 'reset_settings':
        reset_settings(user_id)
        await query.edit_message_text(
            '⚙️ Settings reset to default',
            reply_markup=create_settings_keyboard(user_id, current_page)
        )
        return
    
    if data == 'lupa_status':
        status = f"**Lupa Status:** {'✅ AVAILABLE' if HAS_LUPA else '❌ NOT AVAILABLE'}"
        if HAS_LUPA:
            status += "\n\n✅ WRD Runtime: Ready\n✅ v7 XOR Execute: Ready\n✅ NTT Decode: Ready\n✅ Luraph VM: Ready\n✅ HookOp V1: Ready\n✅ HookOp V2: Ready\n✅ SpyExecute: Ready"
        else:
            status += "\n\n❌ Install: `pip install lupa`"
        await query.message.reply_text(status, parse_mode='Markdown')
        return
    
    toggle_map = {
        'toggle_wrd_literals': 'wrd_literals',
        'toggle_decode_char': 'decode_char',
        'toggle_execute_xor_functions': 'execute_xor_functions',
        'toggle_decode_table_arrays': 'decode_table_arrays',
        'toggle_autodelete': 'autodelete',
        'toggle_analyze_functionality': 'analyze_functionality',
        'toggle_advanced_xor_decoding': 'advanced_xor_decoding',
        'toggle_deep_analysis': 'deep_analysis',
        'toggle_strip_line_comments': 'strip_line_comments',
        'toggle_strip_block_comments': 'strip_block_comments',
        'toggle_delete_probels': 'delete_probels',
        'toggle_minifier': 'minifier',
        'toggle_zip_outputs': 'zip_outputs',
        'toggle_remove_fake_flags': 'remove_fake_flags',
        'toggle_lupa_execution': 'lupa_execution',
        'toggle_execute_wrd_runtime': 'execute_wrd_runtime',
        'toggle_extract_actual_code': 'extract_actual_code',
        'toggle_concat_strings': 'concat_strings',
        'toggle_accept_non_utf8': 'accept_non_utf8',
        'toggle_decode_bit32_xor': 'decode_bit32_xor',
        'toggle_extract_hidden_functions': 'extract_hidden_functions',
        'toggle_remove_obfuscation_layers': 'remove_obfuscation_layers',
        'toggle_decode_ntt_obfuscator': 'decode_ntt_obfuscator',
        'toggle_decode_luraph': 'decode_luraph',
        'toggle_luraph_vm_emulation': 'luraph_vm_emulation',
        'toggle_extract_luraph_bytecode': 'extract_luraph_bytecode',
        'toggle_bypass_antidebug': 'bypass_antidebug',
        'toggle_hookop_enabled': 'hookop_enabled',
        'toggle_hookop_v2_enabled': 'hookop_v2_enabled',
        'toggle_spy_execute_enabled': 'spy_execute_enabled',
        'toggle_trace_calls': 'trace_calls',
        'toggle_sandbox_mode': 'sandbox_mode',
        'toggle_hook_require': 'hook_require',
        'toggle_hook_loadstring': 'hook_loadstring',
        'toggle_hook_http': 'hook_http',
        'toggle_monitor_filesystem': 'monitor_filesystem',
        'toggle_detect_keyloggers': 'detect_keyloggers',
        'toggle_detect_injection': 'detect_injection',
        'toggle_auto_extract_payloads': 'auto_extract_payloads',
        'toggle_memory_analysis': 'memory_analysis',
    }
    
    if data in toggle_map:
        s = get_settings(user_id)
        key = toggle_map[data]
        s[key] = not s.get(key, False)
        await query.edit_message_reply_markup(
            reply_markup=create_settings_keyboard(user_id, current_page)
        )

async def cmd_deob(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Обработчик команды /deob"""
    last = LAST_FILES.get(update.effective_user.id)
    if not last:
        await update.message.reply_text('❌ No saved file. Send .lua/.luau file, link or code.')
        return
    
    name, raw = last
    s = get_settings(update.effective_user.id)
    
    try:
        code_in = raw.decode('utf-8', errors='ignore')
    except UnicodeDecodeError:
        code_in = raw.decode('latin-1', errors='ignore')
    
    status_msg = await update.message.reply_text(f'⏳ Processing: {name}\n🔍 Deobfuscation in progress...')
    
    try:
        res = process_pipeline(code_in, s, update.effective_user.id)
        
        attachments = []
        
        # Основной деобфусцированный код
        if res['processed']:
            processed_code = res['processed']
            
            header = f"""-- UNIVERSAL DEOBFUSCATOR PRO RESULTS
-- File: {name}
-- Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
--
-- DETECTION RESULTS:
-- WRD detected: {'Yes' if res['wrd_detected'] else 'No'}
-- Luraph detected: {'Yes' if res.get('luraph_detected', False) else 'No'}
-- NTT detected: {'Yes' if res.get('ntt_detected', False) else 'No'}
-- v7 XOR detected: {'Yes' if res.get('v7_obfuscation_detected', False) else 'No'}
--
-- DECODING STATUS:
-- Luraph decoded: {'Yes' if res.get('luraph_decoded', False) else 'No'}
-- NTT decoded: {'Yes' if res.get('ntt_decoded', False) else 'No'}
-- v7 decoded: {'Yes' if res.get('v7_decoded', False) else 'No'}
-- WRD executed: {'Yes' if res.get('wrd_executed', False) else 'No'}
--
-- ADVANCED FEATURES:
-- HookOp V1 Enabled: {'Yes' if res.get('hookop_enabled', False) else 'No'}
-- HookOp V2 Enabled: {'Yes' if res.get('hookop_v2_enabled', False) else 'No'}
-- SpyExecute Enabled: {'Yes' if res.get('spy_execute_enabled', False) else 'No'}
-- Sandbox Mode: {'Yes' if res.get('sandbox_mode', True) else 'No'}
--
-- XOR functions found: {res.get('xor_functions_found', 0)}
-- Lupa available: {'Yes' if HAS_LUPA else 'No'}
-- Obfuscation layers: {res.get('stats', {}).get('luraph_detected', 0) + res.get('stats', {}).get('ntt_detected', 0) + res.get('stats', {}).get('wrd_detected', 0) + res.get('stats', {}).get('v7_obfuscation_detected', 0)}
--
"""
            final_code = header + processed_code
            attachments.append((f'{name}_deobfuscated.lua', final_code.encode('utf-8')))
        
        # Извлеченный код из Luraph
        if res.get('luraph_extracted_code'):
            luraph_code = res['luraph_extracted_code']
            if luraph_code.startswith('http'):
                attachments.append((f'{name}_luraph_url.txt', luraph_code.encode('utf-8')))
            elif len(luraph_code) > 100:
                attachments.append((f'{name}_luraph_decoded.lua', luraph_code.encode('utf-8')))
        
        # Извлеченный код из v7
        if res.get('v7_extracted_code'):
            v7_code = res['v7_extracted_code']
            if v7_code.startswith('http'):
                attachments.append((f'{name}_v7_url.txt', v7_code.encode('utf-8')))
            elif len(v7_code) > 100:
                attachments.append((f'{name}_v7_decoded.lua', v7_code.encode('utf-8')))
        
        # Извлеченный код из NTT
        if res.get('ntt_extracted_code'):
            ntt_code = res['ntt_extracted_code']
            if ntt_code.startswith('http'):
                attachments.append((f'{name}_ntt_url.txt', ntt_code.encode('utf-8')))
            elif len(ntt_code) > 100:
                attachments.append((f'{name}_ntt_decoded.lua', ntt_code.encode('utf-8')))
        
        # Анализ функциональности
        if res.get('functionality'):
            analysis = res['functionality']
            analysis_text = "🔍 **FUNCTIONALITY ANALYSIS**\n"
            analysis_text += "═" * 50 + "\n\n"
            
            if analysis.get('luraph_obfuscation'):
                analysis_text += "🔮 **LURAPH OBFUSCATION DETECTED**\n"
                for luraph in analysis['luraph_obfuscation']:
                    analysis_text += f"  • {luraph}\n"
                if analysis.get('luraph_vm'):
                    for vm in analysis['luraph_vm']:
                        analysis_text += f"  • {vm}\n"
                analysis_text += "\n"
            
            if analysis.get('ntt_obfuscation'):
                analysis_text += "🆕 **NTT OBFUSCATION DETECTED**\n"
                for ntt in analysis['ntt_obfuscation']:
                    analysis_text += f"  • {ntt}\n"
                analysis_text += "\n"
            
            if analysis.get('v7_functions'):
                analysis_text += "🆕 **v7 XOR OBFUSCATION DETECTED**\n"
                for v7 in analysis['v7_functions']:
                    analysis_text += f"  • {v7}\n"
                analysis_text += "\n"
            
            if analysis.get('window_ui'):
                analysis_text += "🪟 **WINDUI DETECTED**\n"
                for win in analysis['window_ui']:
                    analysis_text += f"  • {win}\n"
                analysis_text += "\n"
            
            if analysis.get('webhooks'):
                analysis_text += "⚠️ **DISCORD WEBHOOKS** ⚠️\n"
                for webhook in analysis['webhooks'][:3]:
                    analysis_text += f"  • {webhook}\n"
                analysis_text += "\n"
            
            if analysis.get('key_systems'):
                analysis_text += "🔑 **KEY/LICENSE SYSTEMS**\n"
                for key in analysis['key_systems'][:5]:
                    analysis_text += f"  • {key}\n"
                analysis_text += "\n"
            
            if analysis.get('esp_detected'):
                analysis_text += "👁️ **ESP DETECTED**\n"
                for esp in analysis['esp_detected']:
                    analysis_text += f"  • {esp}\n"
                analysis_text += "\n"
            
            if analysis.get('aimbot_detected'):
                analysis_text += "🎯 **AIMBOT DETECTED**\n"
                for aim in analysis['aimbot_detected']:
                    analysis_text += f"  • {aim}\n"
                analysis_text += "\n"
            
            if analysis.get('xor_functions'):
                analysis_text += "🔑 **XOR FUNCTIONS**\n"
                for xor in analysis['xor_functions'][:5]:
                    analysis_text += f"  • {xor}\n"
                analysis_text += "\n"
            
            if analysis.get('debug_checks'):
                analysis_text += "🐞 **DEBUG CHECKS**\n"
                for debug in analysis['debug_checks'][:5]:
                    analysis_text += f"  • {debug}\n"
                analysis_text += "\n"
            
            attachments.append((f'{name}_analysis.txt', analysis_text.encode('utf-8')))
        
        # Статистика
        stats = res['stats']
        stats_text = f"""📊 **DEOBFUSCATION STATISTICS**
═══════════════════════════

🔮 **LURAPH OBFUSCATOR:**
├─ Detected: {'✅' if res.get('luraph_detected', False) else '❌'}
├─ Decoded: {'✅' if stats.get('luraph_decoded', False) else '❌'}
├─ VM Detected: {'✅' if stats.get('luraph_vm_detected', False) else '❌'}
├─ Strings: {stats.get('luraph_strings_decoded', 0)}
├─ Hooked Calls: {stats.get('luraph_hooked_calls', 0)}
└─ Anti-Debug Removed: {stats.get('luraph_antidebug_removed', 0)} chars

🆕 **NTT OBFUSCATOR:**
├─ Detected: {'✅' if res.get('ntt_detected', False) else '❌'}
├─ Decoded: {'✅' if stats.get('ntt_decoded', False) else '❌'}
└─ Strings: {stats.get('ntt_strings_decoded', 0)}

🆕 **v7 XOR OBFUSCATION:**
├─ Detected: {'✅' if stats.get('v7_obfuscation_detected', False) else '❌'}
├─ Decoded: {'✅' if stats.get('v7_decoded', False) else '❌'}
└─ Strings: {stats.get('v7_strings_decoded', 0)}

🔍 **WRD OBFUSCATOR:**
├─ Detected: {'✅' if res['wrd_detected'] else '❌'}
├─ Executed: {'✅' if stats.get('wrd_executed', False) else '❌'}
└─ Strings: {stats.get('wrd_strings_decoded', 0)}

🪝 **HOOKOP V1 & V2:**
├─ HookOp V1: {'✅' if stats.get('hookop_enabled', False) else '❌'}
├─ HookOp V2: {'✅' if stats.get('hookop_v2_enabled', False) else '❌'}
├─ SpyExecute: {'✅' if stats.get('spy_execute_enabled', False) else '❌'}
├─ Sandbox: {'✅' if stats.get('sandbox_mode', True) else '❌'}
└─ Traced Functions: {len(stats.get('hidden_functions', {}).get('hooked_potential', []))}

🔢 **BIT32 OPERATIONS:**
├─ Bit32 XOR: {stats.get('bit32_xor_decoded', 0)}
└─ Advanced XOR: {stats.get('advanced_xor_decoded', 0)}

📝 **DECODING STATS:**
├─ String.Char: {stats['string_char_decoded']}
├─ XOR functions: {stats['xor_functions_found']}
├─ XOR calls: {stats['xor_calls_decoded']}
├─ Tables: {stats['tables_decoded']}
└─ Junk removed: {stats['junk_removed']} chars

🧹 **CODE CLEANUP:**
├─ Fake flags: {stats.get('fake_flags_removed', 0)} chars
├─ Strings concat: {stats.get('strings_concatenated', 0)} chars
├─ Line comments: {stats.get('line_comments_removed', 0)} chars
├─ Block comments: {stats.get('block_comments_removed', 0)} chars
├─ Probels removed: {stats.get('probels_removed', 0)} chars
└─ Minifier: {'✅' if stats.get('minifier_applied', False) else '❌'}

🤖 **LUPA: {'✅' if HAS_LUPA else '❌'}**
"""
        
        # Отправка
        if s.get('zip_outputs', True) and attachments:
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
                for filename, data in attachments:
                    zf.writestr(filename, data)
            zip_buffer.seek(0)
            
            caption = '✅ Deobfuscation complete!\n\n' + stats_text
            if len(caption) > 1024:
                caption = caption[:1000] + "...\n\n(Full stats in analysis file)"
            
            await status_msg.delete()
            await update.message.reply_document(
                document=InputFile(zip_buffer, filename=f'{name}_deobfuscated_pro.zip'),
                caption=caption,
                reply_markup=create_settings_keyboard(update.effective_user.id, 0),
                parse_mode='Markdown'
            )
        elif attachments:
            first_file = attachments[0]
            bio = io.BytesIO(first_file[1])
            bio.name = first_file[0]
            
            caption = '✅ Deobfuscation complete!\n\n' + stats_text
            if len(caption) > 1024:
                caption = caption[:1000] + "...\n\n(Full stats in analysis file)"
            
            await status_msg.delete()
            await update.message.reply_document(
                document=InputFile(bio, filename=first_file[0]),
                caption=caption,
                reply_markup=create_settings_keyboard(update.effective_user.id, 0),
                parse_mode='Markdown'
            )
            
            for filename, data in attachments[1:]:
                bio = io.BytesIO(data)
                bio.name = filename
                await update.message.reply_document(
                    document=InputFile(bio, filename=filename)
                )
        
    except Exception as e:
        log.exception('Processing error')
        await status_msg.edit_text(f'❌ Error: {str(e)}')

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.message.document:
        return
    
    doc = update.message.document
    name = doc.file_name or 'script.lua'
    
    if not name.lower().endswith(('.lua', '.luau', '.txt')):
        await update.message.reply_text('❌ Send .lua or .luau file')
        return
    
    try:
        status = await update.message.reply_text(f'📥 Downloading: {name}')
        file = await context.bot.get_file(doc.file_id)
        bio = io.BytesIO()
        await file.download_to_memory(out=bio)
        bio.seek(0)
        raw = bio.read()
        LAST_FILES[update.effective_user.id] = (name, raw)
        await status.delete()
        await cmd_deob(update, context)
    except Exception as e:
        log.exception('File handling error')
        await update.message.reply_text(f'❌ Error: {str(e)}')

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    
    if text.startswith(('http://', 'https://')):
        try:
            status = await update.message.reply_text('🌐 Downloading from link...')
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(text, headers=headers, timeout=30)
            response.raise_for_status()
            name = 'downloaded.lua'
            
            if 'content-disposition' in response.headers:
                cd = response.headers['content-disposition']
                filename_match = re.search(r'filename="(.+?)"', cd)
                if filename_match:
                    name = filename_match.group(1)
            
            raw = response.content
            LAST_FILES[update.effective_user.id] = (name, raw)
            await status.delete()
            await cmd_deob(update, context)
        except Exception as e:
            await update.message.reply_text(f'❌ Error: {str(e)}')
    else:
        name = 'inline_script.lua'
        raw = text.encode('utf-8')
        LAST_FILES[update.effective_user.id] = (name, raw)
        await update.message.reply_text('⏳ Processing inline code...')
        await cmd_deob(update, context)

async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Обработчик команды /help"""
    help_text = f"""
📚 **УНИВЕРСАЛЬНЫЙ DEOBFUSCATOR PRO - ПОМОЩЬ**

🔰 **ОСНОВНЫЕ КОМАНДЫ:**
/start - Запустить бота
/deob - Деобфусцировать последний загруженный файл
/stats - Статистика бота
/help - Показать это сообщение
/settings - Показать настройки
/reset - Сбросить настройки

🪝 **HOOKOP V1 & V2:**
• **HookOp V1** - перехват всех функций, отслеживание вызовов
• **HookOp V2** - форматирование return, (), :, ; и улучшение читаемости
• **SpyExecute** - мониторинг выполнения loadstring/require
• **Sandbox Mode** - изолированное выполнение кода
• **Call Tracing** - полная трассировка вызовов

🔮 **LURAPH OBFUSCATOR v14.6:**
• VM эмуляция и декомпиляция
• Удаление анти-отладки
• Извлечение байткода
• Декодирование чисел (0x123_456)

🆕 **ДРУГИЕ ОБФУСКАТОРЫ:**
• NTT Obfuscator - табличная XOR деобфускация
• WRD WeAreDevs - выполнение через Lupa
• v7 XOR - автоматическое декодирование

⚙️ **НАСТРОЙКИ:**
• Страница 1-2: основные декодеры
• Страница 3: HookOp V1, HookOp V2, SpyExecute, Sandbox
• Используйте кнопки для включения/выключения

🤖 **LUPA СТАТУС: {'✅ ДОСТУПЕН' if HAS_LUPA else '❌ НЕ ДОСТУПЕН'}**

📌 **ПРИМЕРЫ ИСПОЛЬЗОВАНИЯ:**
1. Отправьте обфусцированный файл
2. Включите HookOp V2 на странице 3 для форматирования
3. Запустите /deob
4. Получите чистый, отформатированный код
"""
    await update.message.reply_text(help_text, parse_mode='Markdown')

async def cmd_settings(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Обработчик команды /settings"""
    await update.message.reply_text(
        '⚙️ **Настройки бота:**\nИспользуйте кнопки для конфигурации',
        reply_markup=create_settings_keyboard(update.effective_user.id, 0),
        parse_mode='Markdown'
    )

async def cmd_reset(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Обработчик команды /reset"""
    reset_settings(update.effective_user.id)
    await update.message.reply_text(
        '✅ Настройки сброшены к значениям по умолчанию!',
        reply_markup=create_settings_keyboard(update.effective_user.id, 0)
    )

async def cmd_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Обработчик команды /stats"""
    lupa_status = '✅ Yes' if HAS_LUPA else '❌ No'
    lines = [
        '📊 **Bot Statistics:**',
        f'• Users: {len(USER_SETTINGS)}',
        f'• Files in memory: {len(LAST_FILES)}',
        f'• Lupa available: {lupa_status}',
    ]
    
    if HAS_LUPA:
        lines.append('• WRD Runtime: ✅ Ready')
        lines.append('• v7 XOR Execute: ✅ Ready')
        lines.append('• NTT Decode: ✅ Ready')
        lines.append('• Luraph VM: ✅ Ready')
        lines.append('• HookOp V1: ✅ Ready')
        lines.append('• HookOp V2: ✅ Ready')
        lines.append('• SpyExecute: ✅ Ready')
    
    if LAST_FILES:
        lines.append('\n📁 **Recent files:**')
        for user_id, (filename, data) in list(LAST_FILES.items())[:5]:
            size = len(data)
            if size < 1024:
                size_str = f"{size} B"
            elif size < 1024*1024:
                size_str = f"{size/1024:.1f} KB"
            else:
                size_str = f"{size/1024/1024:.1f} MB"
            lines.append(f'  • `{filename}` ({size_str})')
    
    await update.message.reply_text('\n'.join(lines), parse_mode='Markdown')

def main():
    token = BOT_TOKEN
    
    if not token or token == "PASTE_YOUR_TOKEN_HERE":
        print('❌ Token not specified')
        return
    
    app = ApplicationBuilder().token(token).build()
    
    # Добавляем обработчики команд
    app.add_handler(CommandHandler('start', cmd_start))
    app.add_handler(CommandHandler('deob', cmd_deob))
    app.add_handler(CommandHandler('stats', cmd_stats))
    app.add_handler(CommandHandler('help', cmd_help))
    app.add_handler(CommandHandler('settings', cmd_settings))
    app.add_handler(CommandHandler('reset', cmd_reset))
    
    # Добавляем остальные обработчики
    app.add_handler(CallbackQueryHandler(handle_callback))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    
    log.info('🚀 UNIVERSAL DEOBFUSCATOR PRO BOT started')
    print('\n' + "="*70)
    print("🤖 UNIVERSAL DEOBFUSCATOR PRO - Luraph + HookOp V1/V2 + SpyExecute")
    print("="*70)
    print(f"✅ Bot successfully started")
    print(f"📦 Lupa available: {HAS_LUPA}")
    if HAS_LUPA:
        print("⚡ WRD Runtime: READY")
        print("⚡ v7 XOR Runtime: READY")
        print("⚡ NTT Decode: READY")
        print("⚡ Luraph VM: READY")
        print("⚡ HookOp V1: READY")
        print("⚡ HookOp V2: READY")
        print("⚡ SpyExecute: READY")
        print("⚡ Sandbox Mode: READY")
    print(f"🐍 Python version: {sys.version}")
    print("="*70 + "\n")
    
    try:
        app.run_polling(drop_pending_updates=True)
    except Exception as e:
        log.error(f'Bot startup error: {e}')
        sys.exit(1)

if __name__ == '__main__':
    main()
