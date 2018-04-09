//#include "libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
//#include "algebra/fields/field_utils.hpp"
/*
#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/common/utils.hpp"
*/
using namespace libsnark;

const size_t sha256_digest_len = 256;
const size_t tree_depth = 16;
/*
computed by:

        unsigned long long bitlen = 256;

        unsigned char padding[32] = {0x80, 0x00, 0x00, 0x00, // 24 bytes of padding
                                     0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00,
                                     bitlen >> 56, bitlen >> 48, bitlen >> 40, bitlen >> 32, // message length
                                     bitlen >> 24, bitlen >> 16, bitlen >> 8, bitlen
                                    };

        std::vector<bool> padding_bv(256);

        convertBytesToVector(padding, padding_bv);

        printVector(padding_bv);
*/
bool sha256_padding[256] = {1,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1, 0,0,0,0,0,0,0,0};

template<typename FieldT, typename HashT>
class toy_gadget : public gadget<FieldT> {
public:
    
    pb_variable_arrray<FieldT> input_as_field_elements;
    std::shared_ptr<multipacking_gadget<FieldT> > pack_inputs;   // 将 primary input 打包成 field 元素的 gadget
    pb_variable_array<FieldT> input_as_bits;

    std::shared_ptr<digest_variable<FieldT> > root_digest;
    std::shared_ptr<digest_variable<FieldT> > prev_leaf_digest;
    std::shared_ptr<digest_variable<FieldT> > leaf_digest;

    std::shared_ptr<merkle_authentication_path_variable<FieldT, HashT> > path_var;
    std::shared_ptr<merkle_tree_check_read_gadget<FieldT, HashT> > ml;
    pb_variable_array<FieldT> address_bits_va;
    pb_variable<FieldT> flag;

    std::shared_ptr<block_variable<FieldT> > h_prev_leaf_block;  // 512 bit block that constraints prev_leaf + padding
    std::shared_ptr<sha256_compression_function_gadget<FieldT> > h_prev_leaf_gadget; //hashing gadget for prev_leaf

    pb_variable<FieldT> zero;
    pb_variable_array<FieldT> padding_var; /* SHA256 length padding */

    toy_gadget(protoboard<FieldT> &pb)
    : gadget<FieldT>(pb, "toy_gadget"){

        // set pb's primary_input_size
        {
            const size_t input_size_in_field_element = div_ceil(2 * sha256_digest_len, FieldT::capacity());
            input_as_field_elements.allocate(pb, input_size_in_field_element, "input_as_field_elements");
            this->pb.set_input_size(input_size_in_field_element);
        }

        prev_leaf_digest.reset(new digest_variable<FieldT>(this->pb, sha256_digest_len, "prev_leaf_digest"));
        root_digest.reset(new digest_variable<FieldT>(this->pb, sha256_digest_len, "root_digest"));
        leaf_digest.reset(new digest_variable<FieldT>(this->pb, sha256_digest_len, "leaf_digest"));

        input_as_bits.insert(input_as_bits.end(), prev_leaf_digest.begin(), prev_leaf_digest.end());
        input_as_bits.insert(input_as_bits.end(), root_digest.begin(), root_digest.end());

        /*
        flag is true : when packing src/target root to field, copy src root (computed root according to leaf/path)
        to target root, so when generating witness, root_digest must be called after merkle_tree_check_read_gadget.
        otherwise root_digest will be overwrite by ml, In this case, given a wrong root, it will pass.
        flag is false : don't do above. so when generating witness, root_digest must be called before merkle_tree_check_read_gadget.
        otherwise, when calling ml generate_r1cs_witness, it will be packing empty/wrong target root, causing packed_source and
        packed_target not equal, it will not pass. 因为在调用 ml->generate_r1cs_witness() 函数的时候，会将 target 对应的位数组打包成
        多个 FieldT 元素，而在调用 ml->generate_r1cs_constraints() 的时候，会将 target 位数组与打包成的多个 FieldT 元素进行等式约束绑定，
        所以如果不在调用 ml->generate_r1cs_witness() 之前先调用 root_digest->generate_r1cs_witness()，那么在调用 ml->generate_r1cs_witness()
        的时候，target 其实是全 0 位数组，将其打包成为多个 FieldT::zero() 的元素，而后再次调用 root_digest->generate_r1cs_witness() 后，
        target 在 pb 中对应的值就会变成 root，那么当再次检查等式约束是否成立时，就会出现 target 位数组与打包好的多个 FieldT 元素不匹配的错误
        */
        flag.allocate(this->pb, "flag");
        address_bits_va.allocate(this->pb, tree_depth, "address_bits");
        zero.allocate(this->pb, "zero");
        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);
        
        // 打包
        pack_inputs.reset(new multipacking_gadget<FieldT>(this->pb, input_as_bits, input_as_field_elements, FieldT::capacity(), FMT(this->annotation_prefix, " pack_inputs")));

        path_var.reset(new merkle_authentication_path_variable<FieldT, HashT>(this->pb, tree_depth, "path_var"));
        ml.reset(new merkle_tree_check_read_gadget<FieldT, HashT>(this->pb, tree_depth, address_bits_va, *leaf_digest,
        *root_digest, *path_var, flag, "ml"));

        for (size_t i = 0; i < 256; ++i) {
            if (sha256_padding[i])
                padding_var.emplace_back(ONE);
            else
                padding_var.emplace_back(zero);
        }

        h_prev_leaf_block.reset(new block_variable<FieldT> (this->pb, {prev_leaf_digest->bits,
          padding_var}, "h_prev_leaf_block"
        ));
        h_prev_leaf_gadget.reset(new sha256_compression_function_gadget<FieldT>(this->pb, IV,
        h_prev_leaf_block->bits, *leaf_digest, "h_prev_leaf_gadget"));
    }

    void generate_r1cs_constraints()
    {
        pack_inputs->generate_r1cs_constraints(true);

        //prev_leaf_digest->generate_r1cs_constraints();
        h_prev_leaf_gadget->generate_r1cs_constraints();
        generate_r1cs_equals_const_constraint<FieldT>(this->pb, zero, FieldT::zero(), "zero");
        path_var->generate_r1cs_constraints();
        ml->generate_r1cs_constraints();
    }
    void generate_r1cs_witness(const bit_vector &prev_leaf, const bit_vector &leaf,
                              const bit_vector &root, const size_t address,
                              const bit_vector &address_bits, const std::vector<merkle_authentication_node> &path)
    {
        this->pb.val(flag) = FieldT::one();
        this->pb.val(zero) = FieldT::zero();
        prev_leaf_digest->generate_r1cs_witness(prev_leaf);
        h_prev_leaf_gadget->generate_r1cs_witness();

        pack_inputs->generate_r1cs_witness_from_bits();
        leaf_digest->generate_r1cs_witness(leaf);
        address_bits_va.fill_with_bits(this->pb, address_bits);
        std::cout << "fff" << "\n";
        std::cout << "hhhhh" << "\n";
        path_var->generate_r1cs_witness(address, path);
        ml->generate_r1cs_witness();

        //make sure that read checker didn't accidentally overwrite anything

        address_bits_va.fill_with_bits(this->pb, address_bits);
        leaf_digest->generate_r1cs_witness(leaf);
        root_digest->generate_r1cs_witness(root);
    }
};

template<typename FieldT>
r1cs_primary_input<FieldT> l_input_map(const bit_vector &h1,
                                             const bit_vector &h2,
                                            )
{
    // Construct the multipacked field points which encode
    // the verifier's knowledge. This is the "dual" of the
    // multipacking gadget logic in the constructor.
    assert(h1.size() == sha256_digest_len);
    assert(h2.size() == sha256_digest_len);

    bit_vector input_as_bits;
    input_as_bits.insert(input_as_bits.end(), h1.begin(), h1.end());
    input_as_bits.insert(input_as_bits.end(), h2.begin(), h2.end());
    std::vector<FieldT> input_as_field_elements = pack_bit_vector_into_field_element_vector<FieldT>(input_as_bits);
    return input_as_field_elements;
}
