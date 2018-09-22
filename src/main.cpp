#include <ctime>
#include <cstdlib>
#include "snark.hpp"
#include <sys/time.h>

using namespace libsnark;
using namespace std;

int main(void) {
    default_r1cs_ppzksnark_pp::init_public_params();
    typedef Fr<default_r1cs_ppzksnark_pp> FieldT;
    auto keypair = generate_keypair<default_r1cs_ppzksnark_pp, sha256_two_to_one_hash_gadget<FieldT> >();

    bit_vector leaf = int_list_to_bits({183, 231, 178, 111, 197, 66, 169, 241, 210, 48, 239, 205, 118, 75, 152, 233, 23, 244, 68, 121, 155, 134, 181, 131, 32, 157, 253, 177, 49, 186, 62, 132}, 8);
    //bit_vector prev_leaf = int_list_to_bits({18, 231, 178, 111, 197, 66, 169, 241, 210, 48, 239, 205, 118, 75, 152, 233, 23, 244, 68, 121, 155, 134, 181, 131, 32, 157, 253, 177, 49, 186, 62, 132}, 8);

    bit_vector prev_leaf = int_list_to_bits({78, 144, 206, 42, 80, 100, 176, 75, 200, 232, 113, 98, 19, 218, 162, 124, 58, 186, 16, 209, 143, 237, 155, 247, 76, 51, 189, 234, 207, 145, 110, 196}, 8);
    std::vector<merkle_authentication_node> path;

    bit_vector prev_hash = leaf;
    bit_vector root;
    bit_vector address_bits;
    size_t address = 0;

    generate_merkle_and_branch<sha256_two_to_one_hash_gadget<Fr<default_r1cs_ppzksnark_pp> > > (prev_leaf, leaf, root, address, address_bits, path);

    cout << "generating proof...." << endl;
    struct timeval start, end;
    gettimeofday(&start, NULL);
    auto proof = generate_proof<default_r1cs_ppzksnark_pp, sha256_two_to_one_hash_gadget<FieldT> >(keypair.pk, prev_leaf, leaf, root, address, address_bits, path);
    gettimeofday(&end, NULL);
    cout << "Proof generated!" << endl;
    cout << "take time : " << (end.tv_sec - start.tv_sec) << " second " << (end.tv_usec - start.tv_usec) <<  " microseconds" << endl;

    assert(verify_proof<default_r1cs_ppzksnark_pp>(keypair.vk, *proof, prev_leaf, root));
    gettimeofday(&start, NULL);

    cout << "verify proof finish!" << endl;
    cout << "take time : " << (start.tv_sec - end.tv_sec) << " second " << (start.tv_usec - end.tv_usec) << " microseconds" << endl;

    return 0;
}
