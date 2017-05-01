#include "libsnark/common/data_structures/merkle_tree.hpp"  //for the merkle_authentication_node
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"  //for the default_r1cs_ppzksnark_pp
#include "libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"   // for the sha256_two_to_one_hash_gadget
#include "libsnark/common/utils.hpp"  //for the bit_vector
#include "libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp" // for the merkle_tree_check_read_gadget
#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "algebra/fields/field_utils.hpp"
#include "libsnark/common/utils.hpp"
#include <boost/optional.hpp>
#include "gadget.hpp"

using namespace libsnark;
using namespace std;

template<typename HashT>
void generate_merkle_and_branch(bit_vector &prev_leaf, bit_vector &leaf, bit_vector &root,
                                size_t &address, bit_vector &address_bits,
                                std::vector<merkle_authentication_node> &path) {

    bit_vector prev_hash = leaf;
    path = std::vector<merkle_authentication_node> (tree_depth);

    for (long level = tree_depth - 1; level >= 0; --level) {
        const bool computed_is_right = (std::rand() % 2);
        address |= (computed_is_right ? 1ul << (tree_depth-1-level) : 0);
        address_bits.push_back(computed_is_right);
        bit_vector other(sha256_digest_len);
        std::generate(other.begin(), other.end(), [&](){return std::rand()%2;});
        bit_vector block = prev_hash;
        block.insert(computed_is_right ? block.begin() : block.end(), other.begin(), other.end());
        bit_vector h = HashT::get_hash(block);

        path[level] = other;
        prev_hash = h;
    }

    root = prev_hash;
}

template<typename ppzksnark_ppT, typename HashT>
r1cs_ppzksnark_keypair<ppzksnark_ppT> generate_keypair()
{
    typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;
    toy_gadget<FieldT, HashT> g(pb);
    g.generate_r1cs_constraints();
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

    cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    cout << "auxiliary input size : " << constraint_system.auxiliary_input_size << endl;
    cout << "primary_input size : " << constraint_system.primary_input_size << endl;

    return r1cs_ppzksnark_generator<ppzksnark_ppT>(constraint_system);
}

template<typename ppzksnark_ppT, typename HashT>
boost::optional<r1cs_ppzksnark_proof<ppzksnark_ppT>> generate_proof(r1cs_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
                                                                   const bit_vector &prev_leaf,
                                                                   const bit_vector &leaf,
                                                                   const bit_vector &root,
                                                                   const size_t address,
                                                                   const bit_vector &address_bits,
                                                                   const std::vector<merkle_authentication_node> &path
                                                                   )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;
    toy_gadget<FieldT, HashT> g(pb);
    g.generate_r1cs_constraints();
    g.generate_r1cs_witness(prev_leaf, leaf, root, address, address_bits, path);

    if (!pb.is_satisfied()) {
        return boost::none;
    }

    return r1cs_ppzksnark_prover<ppzksnark_ppT>(proving_key, pb.primary_input(), pb.auxiliary_input());
}

template<typename ppzksnark_ppT>
bool verify_proof(r1cs_ppzksnark_verification_key<ppzksnark_ppT> verification_key,
                  r1cs_ppzksnark_proof<ppzksnark_ppT> proof,
                  const bit_vector &prev_leaf,
                  const bit_vector &root
                 )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    //const r1cs_primary_input<FieldT> input = l_input_map<FieldT>(h1, h2, x);

    r1cs_primary_input<FieldT> input;
    input.insert(input.end(), prev_leaf.begin(), prev_leaf.end());
    input.insert(input.end(), root.begin(), root.end());

    return r1cs_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(verification_key, input, proof);
}
