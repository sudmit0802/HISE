//#define LOG

#include "../api/hise_sign_api.hpp"

int main()
{
    auto setup_pair = setup();
    auto ctx = std::get<0>(setup_pair);
    auto super_key = std::get<1>(setup_pair);

    auto keys = keygen(ctx);
    auto public_key = std::get<0>(keys);
    auto private_key = std::get<1>(keys);

    std::string msg("hi");

    auto cipher_text = encrypt(ctx, public_key, msg);
    auto decrypted_text = decrypt(ctx, private_key, cipher_text);
    
    std::cout<<decrypted_text<<std::endl;

    return 0;
}