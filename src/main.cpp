// #define LOG

#include "../api/hise_sign_api.hpp"

// Basic test. Boss can decrypt common communication member's messages, others can't
void test_1()
{
    std::cout << "Start test #1" << std::endl;

    auto setup_pair = setup();
    auto ctx = std::get<0>(setup_pair);
    auto super_key = std::get<1>(setup_pair);
    std::cout << "A context and SUPERVISOR's private key are generated!" << std::endl;

    auto keys = keygen(ctx);
    auto public_key = std::get<0>(keys);
    auto private_key = std::get<1>(keys);
    std::cout << "A COMMONER's keypair is generated!" << std::endl;

    std::string msg_ref("THIS IS A TEST PLAINTEXT STRING");
    std::cout << "A test string was generated: " << msg_ref << std::endl;

    std::string msg_1(msg_ref);
    auto cipher_text_1 = encrypt(ctx, public_key, msg_1);
    std::cout << "Encrypted by COMMONER: " << cipher_text_1.Y2 << std::endl;
    auto decrypted_text_1 = decrypt(ctx, private_key, cipher_text_1);
    std::cout << "Decrypted by COMMONER: " << decrypted_text_1 << std::endl;

    std::string msg_2(msg_ref);
    auto cipher_text_2 = encrypt(ctx, public_key, msg_2);
    std::cout << "Encrypted by SUPERVISOR: " << cipher_text_2.Y2 << std::endl;
    auto decrypted_text_2 = super_decrypt(ctx, super_key, cipher_text_2);
    std::cout << "Decrypted by SUPERVISOR: " << decrypted_text_2 << std::endl;

    auto keys_at = keygen(ctx);
    auto public_key_at = std::get<0>(keys_at);
    auto private_key_at = std::get<1>(keys_at);
    std::cout << "A CHECKER's keypair is generated!" << std::endl;
    auto decrypted_text_3 = decrypt(ctx, private_key_at, cipher_text_1);
    std::cout << "Decrypted by CHECKER: " << decrypted_text_3 << std::endl;

    std::cout << "Finish test #1" << std::endl
              << std::endl;
    return;
}

// Boss can not forge a signature
void test_2()
{
    std::cout << "Start test #2" << std::endl;

    std::cout << "Finish test #2" << std::endl
              << std::endl;

    return;
}

// Boss can communicate with others as typical user using his super key (signing and encrypting)
void test_3()
{
    std::cout << "Start test #3" << std::endl;

    auto setup_pair = setup();
    auto ctx = std::get<0>(setup_pair);
    auto super_key = std::get<1>(setup_pair);
    std::cout << "A context and SUPERVISOR's private key are generated!" << std::endl;

    auto keys = keygen(ctx);
    auto public_key = std::get<0>(keys);
    auto private_key = std::get<1>(keys);
    std::cout << "A COMMONER's keypair is generated!" << std::endl;

    std::string msg_ref("THIS IS A TEST PLAINTEXT STRING");
    std::cout << "A test string was generated: " << msg_ref << std::endl;

    std::string msg_1(msg_ref);
    auto cipher_text_1 = encrypt(ctx, public_key, msg_1);
    std::cout << "Encrypted by COMMONER: " << cipher_text_1.Y2 << std::endl;
    auto decrypted_text_1 = super_decrypt(ctx, super_key, cipher_text_1);
    std::cout << "Decrypted by SUPERVISOR: " << decrypted_text_1 << std::endl;

    std::cout << "Finish test #3" << std::endl
              << std::endl;

    return;
}

// User addition to system, expand key set keeping boss key valid
void test_4()
{
    std::cout << "Start test #4" << std::endl;

    auto setup_pair = setup();
    auto ctx = std::get<0>(setup_pair);
    auto super_key = std::get<1>(setup_pair);
    std::cout << "A context and SUPERVISOR's private key are generated!" << std::endl;

    auto keys = keygen(ctx);
    auto public_key = std::get<0>(keys);
    auto private_key = std::get<1>(keys);
    std::cout << "A COMMONER's keypair is generated!" << std::endl;

    std::string msg_ref("THIS IS A TEST PLAINTEXT STRING");
    std::cout << "A test string was generated: " << msg_ref << std::endl;

    std::string msg_1(msg_ref);
    auto cipher_text_1 = encrypt(ctx, public_key, msg_1);
    std::cout << "Encrypted by COMMONER: " << cipher_text_1.Y2 << std::endl;
    auto decrypted_text_1 = decrypt(ctx, private_key, cipher_text_1);
    std::cout << "Decrypted by COMMONER: " << decrypted_text_1 << std::endl;

    std::string msg_2(msg_ref);
    auto cipher_text_2 = encrypt(ctx, public_key, msg_2);
    std::cout << "Encrypted by SUPERVISOR: " << cipher_text_2.Y2 << std::endl;
    auto decrypted_text_2 = super_decrypt(ctx, super_key, cipher_text_2);
    std::cout << "Decrypted by SUPERVISOR: " << decrypted_text_2 << std::endl;

    auto keys_ext = keygen(ctx);
    auto public_key_ext = std::get<0>(keys_ext);
    auto private_key_ext = std::get<1>(keys_ext);
    std::cout << "A EXTENSION's keypair is generated!" << std::endl;
    std::string msg_3(msg_ref);
    auto cipher_text_3 = encrypt(ctx, public_key_ext, msg_3);
    std::cout << "Encrypted by COMMONER: " << cipher_text_3.Y2 << std::endl;
    auto decrypted_text_3 = super_decrypt(ctx, super_key, cipher_text_3);
    std::cout << "Decrypted by SUPERVISOR: " << decrypted_text_3 << std::endl;

    std::cout << "Finish test #4" << std::endl
              << std::endl;

    return;
}

// Check key compromise
void test_5()
{
    std::cout << "Start test #5" << std::endl;

    auto setup_pair = setup();
    auto ctx = std::get<0>(setup_pair);
    auto super_key = std::get<1>(setup_pair);
    std::cout << "A context and SUPERVISOR's private key are generated!" << std::endl;

    auto keys = keygen(ctx);
    auto public_key = std::get<0>(keys);
    auto private_key = std::get<1>(keys);
    std::cout << "A COMMONER's keypair is generated!" << std::endl;

    auto keys_ex = keygen(ctx);
    auto public_key_ex = std::get<0>(keys_ex);
    auto private_key_ex = std::get<1>(keys_ex);
    std::cout << "AN EXTRA_COMMONER's keypair is generated!" << std::endl;

    std::string msg_ref("THIS IS A TEST PLAINTEXT STRING");
    std::cout << "A test string was generated: " << msg_ref << std::endl;

    std::string msg_1(msg_ref);
    auto cipher_text_1 = encrypt(ctx, public_key, msg_1);
    std::cout << "Encrypted by COMMONER: " << cipher_text_1.Y2 << std::endl;
    auto decrypted_text_1 = decrypt(ctx, private_key, cipher_text_1);
    std::cout << "Decrypted by COMMONER: " << decrypted_text_1 << std::endl;

    std::string msg_2(msg_ref);
    auto cipher_text_2 = encrypt(ctx, public_key, msg_2);
    std::cout << "Encrypted by SUPERVISOR: " << cipher_text_2.Y2 << std::endl;
    auto decrypted_text_2 = super_decrypt(ctx, super_key, cipher_text_2);
    std::cout << "Decrypted by SUPERVISOR: " << decrypted_text_2 << std::endl;

    auto public_key_at = public_key;
    auto private_key_at = private_key;
    std::cout << "AN ATTACKER's keypair is based on COMMONER'S one (compromised!)" << std::endl;

    std::string msg_3(msg_ref);
    auto cipher_text_3 = encrypt(ctx, public_key, msg_3);
    std::cout << "Encrypted by COMMONER: " << cipher_text_3.Y2 << std::endl;
    auto decrypted_text_3 = decrypt(ctx, private_key_at, cipher_text_3);
    std::cout << "Decrypted by COMMONER: " << decrypted_text_3 << std::endl;

    std::string msg_4(msg_ref);
    auto cipher_text_4 = encrypt(ctx, public_key_ex, msg_4);
    std::cout << "Encrypted by EXTRA_COMMONER: " << cipher_text_4.Y2 << std::endl;
    auto decrypted_text_4 = super_decrypt(ctx, private_key_at, cipher_text_4);
    std::cout << "Decrypted by EXTRA_COMMONER: " << decrypted_text_4 << std::endl;

    std::cout << "Finish test #5" << std::endl
              << std::endl;

    return;
}

int main(int argc, char **argv)
{
    test_1();
    test_2();
    test_3();
    test_4();
    test_5();

    return 0;
}
