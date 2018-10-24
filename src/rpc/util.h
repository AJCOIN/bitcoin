// Copyright (c) 2017-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPC_UTIL_H
#define BITCOIN_RPC_UTIL_H

#include <pubkey.h>
#include <script/standard.h>
#include <univalue.h>

#include <boost/variant/static_visitor.hpp>

#include <string>
#include <vector>

class CKeyStore;
class CPubKey;
class CScript;

CPubKey HexToPubKey(const std::string& hex_in);
CPubKey AddrToPubKey(CKeyStore* const keystore, const std::string& addr_in);
CScript CreateMultisigRedeemscript(const int required, const std::vector<CPubKey>& pubkeys);

UniValue DescribeAddress(const CTxDestination& dest);

class RPCHelpTableRow
{
private:
    std::string m_left;
    const std::string m_right;

public:
    explicit RPCHelpTableRow(const std::string& left, const std::string& right) : m_left(left), m_right(right)
    {
    }

    std::vector<std::string> RightLines() const;
    std::string const& Left() const;
    void PrefixLeft(const std::string& s);
    void SuffixLeft(const std::string& s);
};

class RPCHelpTable
{
private:
    std::string m_name;
    std::vector<RPCHelpTableRow> m_rows;

    size_t PrefixLength() const;

public:
    explicit RPCHelpTable(const std::string& name) : m_name(name) {}

    void AddRow(const RPCHelpTableRow& row);

    std::string ToString() const;
};


struct RPCArg {
    enum class Type {
        OBJ,
        ARR,
        STR,
        NUM,
        BOOL,
        AMOUNT, //!< Special type representing a floating point amount (can be either NUM or STR)
        STR_HEX, //!< Special type that is a STR with only hex chars
    };
    const std::string m_name; //!< The name of the arg (can be empty for inner args)
    const Type m_type;
    const std::vector<RPCArg> m_inner; //!< Only used for arrays or dicts
    const bool m_optional;
    const std::string m_description;

    RPCArg(const std::string& name, const std::string& description, const Type& type, const bool optional)
        : m_name{name}, m_type{type}, m_optional{optional}, m_description(description)
    {
        assert(type != Type::ARR && type != Type::OBJ);
    }

    RPCArg(const std::string& name, const std::string& description, const Type& type, const std::vector<RPCArg>& inner, const bool optional)
        : m_name{name}, m_type{type}, m_inner{inner}, m_optional{optional}, m_description(description)
    {
        assert(type == Type::ARR || type == Type::OBJ);
    }

    std::string ToStringFirstLine(bool shortenIfLong) const;
    std::vector<RPCHelpTableRow> ToTableRows(int i) const;

private:
    RPCHelpTableRow ToTableRowSimple(const std::string& prefix) const;
    std::vector<RPCHelpTableRow> ToTableRowsObj(const std::string& prefix) const;
    std::vector<RPCHelpTableRow> ToTableRowsStructure(const std::string& prefix) const;
    std::string ToStringObjFirstLine() const;
    std::string ToTableLeftObj() const;
    std::string ToTableLeft() const;
    std::string TypeString() const;
    std::string TypeAndInfoString() const;
};

class RPCHelpMan
{
public:
    RPCHelpMan(const std::string& name, const std::string& description, const std::vector<RPCArg>& args)
        : m_name{name}, m_args{args}, m_description{description}
    {
    }

    std::string ToString() const;

private:
    const std::string m_name;
    const std::vector<RPCArg> m_args;
    const std::string m_description;

    std::string ToStringFirstLine() const;
    RPCHelpTable ToArgTable() const;
};

#endif // BITCOIN_RPC_UTIL_H
