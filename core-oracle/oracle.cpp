#include <cstdint>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <crypto/SHA.h>
#include <scp/LocalNode.h>
#include <scp/SCPDriver.h>
#include <scp/QuorumSetUtils.h>
#include <util/Logging.h>
#include <util/XDROperators.h>
#include <xdr/Stellar-SCP.h>
#include <xdr/Stellar-types.h>
#include <xdrpp/marshal.h>

using namespace stellar;

static std::vector<uint8_t>
unhex(std::string const& text)
{
    if (text.size() % 2 != 0)
    {
        throw std::invalid_argument("hex input has an odd number of digits");
    }
    std::vector<uint8_t> out;
    out.reserve(text.size() / 2);
    for (size_t i = 0; i + 1 < text.size(); i += 2)
    {
        out.push_back(
            static_cast<uint8_t>(std::stoul(text.substr(i, 2), nullptr, 16)));
    }
    return out;
}

static SCPQuorumSet
qsetFromHex(std::string const& text)
{
    SCPQuorumSet qset;
    auto bytes = unhex(text);
    xdr::xdr_from_opaque(bytes, qset);
    return qset;
}

static NodeID
nodeFromHex(std::string const& text)
{
    auto bytes = unhex(text);
    if (bytes.size() != 32)
    {
        throw std::runtime_error("node id must be 32 bytes");
    }
    NodeID id;
    id.type(PUBLIC_KEY_TYPE_ED25519);
    std::copy(bytes.begin(), bytes.end(), id.ed25519().begin());
    return id;
}

static std::vector<std::string>
split(std::string const& line, char sep)
{
    std::vector<std::string> out;
    std::istringstream in(line);
    std::string field;
    while (std::getline(in, field, sep))
    {
        if (!field.empty())
        {
            out.push_back(field);
        }
    }
    return out;
}

static bool
answerQuorum(std::vector<std::string> const& fields)
{
    auto local = qsetFromHex(fields.at(1));

    std::map<NodeID, SCPEnvelopeWrapperPtr> envelopes;
    std::map<NodeID, SCPQuorumSetPtr> qsets;

    for (size_t i = 2; i < fields.size(); ++i)
    {
        auto parts = split(fields[i], ':');
        auto node = nodeFromHex(parts.at(0));
        auto qset = std::make_shared<SCPQuorumSet>(qsetFromHex(parts.at(1)));

        SCPEnvelope envelope;
        envelope.statement.nodeID = node;
        envelope.statement.slotIndex = 0;
        envelope.statement.pledges.type(SCP_ST_EXTERNALIZE);

        envelopes[node] = std::make_shared<SCPEnvelopeWrapper>(envelope);
        qsets[node] = qset;
    }

    auto lookup = [&qsets](SCPStatement const& st) -> SCPQuorumSetPtr {
        auto it = qsets.find(st.nodeID);
        return it == qsets.end() ? nullptr : it->second;
    };

    return LocalNode::isQuorum(local, envelopes, lookup,
                               [](SCPStatement const&) { return true; });
}

static bool
answerSlice(std::vector<std::string> const& fields)
{
    auto qset = qsetFromHex(fields.at(1));
    std::vector<NodeID> nodes;
    for (size_t i = 2; i < fields.size(); ++i)
    {
        nodes.push_back(nodeFromHex(fields[i]));
    }
    return LocalNode::isQuorumSlice(qset, nodes);
}

static bool
answerSane(std::vector<std::string> const& fields)
{
    auto qset = qsetFromHex(fields.at(1));
    bool extra = fields.at(2) == "1";
    char const* reason = nullptr;
    return isQuorumSetSane(qset, extra, reason);
}

int
main()
{
    std::string line;
    while (std::getline(std::cin, line))
    {
        if (line.empty())
        {
            continue;
        }
        try
        {
            auto fields = split(line, ' ');
            bool answer = false;
            if (fields.at(0) == "quorum")
            {
                answer = answerQuorum(fields);
            }
            else if (fields.at(0) == "slice")
            {
                answer = answerSlice(fields);
            }
            else if (fields.at(0) == "sane")
            {
                answer = answerSane(fields);
            }
            else
            {
                std::cout << "error unknown command" << std::endl;
                continue;
            }
            std::cout << (answer ? "1" : "0") << std::endl;
        }
        catch (std::exception const& e)
        {
            std::cout << "error " << e.what() << std::endl;
        }
    }
    return 0;
}
