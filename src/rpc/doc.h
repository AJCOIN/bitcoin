// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPC_DOC_H
#define BITCOIN_RPC_DOC_H

#include <amount.h>
#include <rpc/protocol.h>
#include <uint256.h>

#include <list>
#include <map>
#include <stdint.h>
#include <string>

class RPCDocExample
{
private:
    const std::string m_description;
    const std::string m_code;

public:
    RPCDocExample(const std::string& description, const std::string& code);
    RPCDocExample(const std::string& code);
    std::string AsText() const;
};

class RPCDocTableRow
{
private:
    const std::string m_code;
    std::vector<std::string> m_types;
    const std::string m_description;

public:
    RPCDocTableRow(const std::string& code);
    RPCDocTableRow(const std::string& code, const std::string& description);
    RPCDocTableRow(const std::string& code, const std::vector<std::string>& types, const std::string& description);
    std::string const& Code() const;
    std::vector<std::string> const& Types() const;
    std::vector<std::string> DescriptionLines() const;
};

class RPCDocTable
{
private:
    std::string m_name;
    std::vector<RPCDocTableRow> m_rows;

    size_t PrefixLength() const;

public:
    RPCDocTable(const std::string& name);
    void AddRow(const RPCDocTableRow& row);

    std::string AsText() const;
};

class RPCDoc
{
private:
    std::string m_methodName;
    std::string m_firstArguments;
    std::string m_description;
    std::vector<RPCDocTable> m_tables;
    std::vector<RPCDocExample> m_examples;

public:
    RPCDoc(std::string methodName, std::string firstArguments);

    RPCDoc& Desc(const std::string& description);
    RPCDoc& Table(const std::string& name);
    RPCDoc& Row(const std::string& code);
    RPCDoc& Row(const std::string& code, const std::string& description);
    RPCDoc& Row(const std::string& code, const std::vector<std::string>& types, const std::string& description);
    RPCDoc& Example(const std::string& code);
    RPCDoc& Example(const std::string& description, const std::string& code);

    RPCDoc& ExampleCli(const std::string& args);
    RPCDoc& ExampleJson(const std::string& args);

    std::string AsText() const;
    std::runtime_error AsError() const;
};

#endif
