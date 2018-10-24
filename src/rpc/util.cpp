// Copyright (c) 2017-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key_io.h>
#include <keystore.h>
#include <rpc/protocol.h>
#include <rpc/util.h>
#include <tinyformat.h>
#include <utilstrencodings.h>

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/split.hpp>

#define FIRSTLINE_MAX_ARG_LENGTH 100

// Converts a hex string to a public key if possible
CPubKey HexToPubKey(const std::string& hex_in)
{
    if (!IsHex(hex_in)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid public key: " + hex_in);
    }
    CPubKey vchPubKey(ParseHex(hex_in));
    if (!vchPubKey.IsFullyValid()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid public key: " + hex_in);
    }
    return vchPubKey;
}

// Retrieves a public key for an address from the given CKeyStore
CPubKey AddrToPubKey(CKeyStore* const keystore, const std::string& addr_in)
{
    CTxDestination dest = DecodeDestination(addr_in);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address: " + addr_in);
    }
    CKeyID key = GetKeyForDestination(*keystore, dest);
    if (key.IsNull()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("%s does not refer to a key", addr_in));
    }
    CPubKey vchPubKey;
    if (!keystore->GetPubKey(key, vchPubKey)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("no full public key for address %s", addr_in));
    }
    if (!vchPubKey.IsFullyValid()) {
       throw JSONRPCError(RPC_INTERNAL_ERROR, "Wallet contains an invalid public key");
    }
    return vchPubKey;
}

// Creates a multisig redeemscript from a given list of public keys and number required.
CScript CreateMultisigRedeemscript(const int required, const std::vector<CPubKey>& pubkeys)
{
    // Gather public keys
    if (required < 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "a multisignature address must require at least one key to redeem");
    }
    if ((int)pubkeys.size() < required) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("not enough keys supplied (got %u keys, but need at least %d to redeem)", pubkeys.size(), required));
    }
    if (pubkeys.size() > 16) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Number of keys involved in the multisignature address creation > 16\nReduce the number");
    }

    CScript result = GetScriptForMultisig(required, pubkeys);

    if (result.size() > MAX_SCRIPT_ELEMENT_SIZE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, (strprintf("redeemScript exceeds size limit: %d > %d", result.size(), MAX_SCRIPT_ELEMENT_SIZE)));
    }

    return result;
}

class DescribeAddressVisitor : public boost::static_visitor<UniValue>
{
public:
    explicit DescribeAddressVisitor() {}

    UniValue operator()(const CNoDestination& dest) const
    {
        return UniValue(UniValue::VOBJ);
    }

    UniValue operator()(const CKeyID& keyID) const
    {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("isscript", false);
        obj.pushKV("iswitness", false);
        return obj;
    }

    UniValue operator()(const CScriptID& scriptID) const
    {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("isscript", true);
        obj.pushKV("iswitness", false);
        return obj;
    }

    UniValue operator()(const WitnessV0KeyHash& id) const
    {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("isscript", false);
        obj.pushKV("iswitness", true);
        obj.pushKV("witness_version", 0);
        obj.pushKV("witness_program", HexStr(id.begin(), id.end()));
        return obj;
    }

    UniValue operator()(const WitnessV0ScriptHash& id) const
    {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("isscript", true);
        obj.pushKV("iswitness", true);
        obj.pushKV("witness_version", 0);
        obj.pushKV("witness_program", HexStr(id.begin(), id.end()));
        return obj;
    }

    UniValue operator()(const WitnessUnknown& id) const
    {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("iswitness", true);
        obj.pushKV("witness_version", (int)id.version);
        obj.pushKV("witness_program", HexStr(id.program, id.program + id.length));
        return obj;
    }
};

UniValue DescribeAddress(const CTxDestination& dest)
{
    return boost::apply_visitor(DescribeAddressVisitor(), dest);
}

std::vector<std::string> RPCHelpTableRow::RightLines() const
{
    std::vector<std::string> res;
    boost::split(res, m_right, boost::is_any_of("\n"));
    return res;
}

std::string const& RPCHelpTableRow::Left() const
{
    return m_left;
}

size_t RPCHelpTable::PrefixLength() const
{
    size_t max = 0;
    for (const auto& row : m_rows) {
        size_t prefix = row.Left().length() + 2;
        if (prefix > max) {
            max = prefix;
        }
    }
    return max;
}

void RPCHelpTable::AddRow(const RPCHelpTableRow& row)
{
    m_rows.emplace_back(row);
}

std::string RPCHelpTable::AsText() const
{
    std::string res;
    res += m_name;
    res += ":\n";

    size_t prefixLen = PrefixLength();
    for (const auto& row : m_rows) {
        const std::string& left = row.Left();
        res += left;
        auto lines = row.RightLines();
        bool firstLine = true;
        for (const auto& line : lines) {
            size_t spaces;
            if (firstLine) {
                spaces = prefixLen - left.length();
            } else {
                spaces = prefixLen;
            }
            res += std::string(spaces, ' ');
            res += line;
            res += "\n";
            firstLine = false;
        }
    }
    return res;
}

std::string RPCHelpMan::ToString() const
{
    std::string ret = ToStringFirstLine();

    if (m_description.empty()) {
        return ret;
    }

    return ret + "\n" + m_description + "\n\n";
}

std::string RPCHelpMan::ToStringFirstLine() const
{
    std::string ret;

    ret += m_name;
    bool is_optional{false};
    for (const auto& arg : m_args) {
        ret += " ";
        if (arg.m_optional) {
            if (!is_optional) ret += "( ";
            is_optional = true;
        } else {
            // Currently we still support unnamed arguments, so any argument following an optional argument must also be optional
            // If support for positional arguments is deprecated in the future, remove this line
            assert(!is_optional);
        }
        ret += arg.ToStringFirstLine(true);
    }
    if (is_optional) ret += " )";
    ret += "\n";

    return ret;
}

std::string RPCArg::ToStringObjFirstLine() const
{
    std::string res = "\"" + m_name + "\"";
    switch (m_type) {
    case Type::STR:
        return res + ":\"str\"";
    case Type::STR_HEX:
        return res + ":\"hex\"";
    case Type::NUM:
        return res + ":n";
    case Type::AMOUNT:
        return res + ":amount";
    case Type::BOOL:
        return res + ":bool";
    case Type::ARR:
        res += ":[";
        for (const auto& i : m_inner) {
            res += i.ToStringFirstLine(false) + ",";
        }
        return res + "...]";
    case Type::OBJ:
        // Currently unused, so avoid writing dead code
        assert(false);

        // no default case, so the compiler can warn about missing cases
    }
    assert(false);
}

std::string RPCArg::ToStringFirstLine(bool shortenIfLong) const
{
    switch (m_type) {
    case Type::STR_HEX:
    case Type::STR: {
        return "\"" + m_name + "\"";
    }
    case Type::NUM:
    case Type::AMOUNT:
    case Type::BOOL: {
        return m_name;
    }
    case Type::OBJ: {
        std::string res;
        for (size_t i = 0; i < m_inner.size();) {
            res += m_inner[i].ToStringObjFirstLine();
            if (++i < m_inner.size()) res += ",";
        }
        res = "{" + res + "}";
        if (shortenIfLong) {
            if (res.length() > FIRSTLINE_MAX_ARG_LENGTH) {
                return m_name;
            }
        }
        return res;
    }
    case Type::ARR: {
        std::string res;
        for (const auto& i : m_inner) {
            res += i.ToStringFirstLine(false) + ",";
        }
        res = "[" + res + "...]";

        if (shortenIfLong) {
            if (res.length() > FIRSTLINE_MAX_ARG_LENGTH) {
                return m_name;
            }
        }
        return res;
    }

        // no default case, so the compiler can warn about missing cases
    }
    assert(false);
}
