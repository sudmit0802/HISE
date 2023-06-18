// #define LOG

#include "../api/hise_sign_api.hpp"

class Master
{
private:
    Global_Escrow_HISE_PP context;
    mcl::bn::G1 public_key;
    mcl::bn::G2 private_key;
    mcl::bn::Fr s;

public:
    Master()
    {
        auto setup_data = setup();
        context = std::get<0>(setup_data);
        public_key = context.epk;
        private_key = std::get<1>(setup_data);
        s = std::get<2>(setup_data);
    }

    Global_Escrow_HISE_PP get_context(void)
    {
        return context;
    }

    Global_Escrow_HISE_CT do_ecnrypt(mcl::bn::G1 &pk, std::string &message)
    {
        return encrypt(context, pk, message);
    }

    std::string do_decrypt(Global_Escrow_HISE_CT &ct)
    {
        return super_decrypt(context, private_key, ct);
    }

    mcl::bn::G2 do_sign(std::string &msg)
    {
        return sign(s, msg);
    }

    bool do_verify(std::string &msg, mcl::bn::G1 &pk, mcl::bn::G2 &sig)
    {
        return verify(context, pk, msg, sig);
    }

    mcl::bn::G1 get_public_key(void)
    {
        return public_key;
    }
};

class Slave
{
private:
    Global_Escrow_HISE_PP context;
    mcl::bn::G1 public_key;
    mcl::bn::G2 private_key;
    mcl::bn::Fr sk;

public:
    Slave(Global_Escrow_HISE_PP &ctx)
    {
        context = ctx;
        auto keys = keygen(context);
        public_key = std::get<0>(keys);
        private_key = std::get<1>(keys);
        sk = std::get<2>(keys);
    }

    Global_Escrow_HISE_CT do_ecnrypt(mcl::bn::G1 &pk, std::string &message)
    {
        return encrypt(context, pk, message);
    }

    std::string do_decrypt(Global_Escrow_HISE_CT &ct)
    {
        return decrypt(context, private_key, ct);
    }

    mcl::bn::G2 do_sign(std::string &msg)
    {
        return sign(sk, msg);
    }

    bool do_verify(std::string &msg, mcl::bn::G1 &pk, mcl::bn::G2 &sig)
    {
        return verify(context, pk, msg, sig);
    }

    mcl::bn::G1 get_public_key(void)
    {
        return public_key;
    }
};

// BOSS DECRYPTS USER'S CIPHERTEXT WHILE ANOTHER USER CAN'T DO IT
void test_1()
{
    std::cout << "Start test #1 - BOSS DECRYPTS USER'S CIPHERTEXT WHILE ANOTHER USER CAN'T DO IT" << std::endl;

    auto boss_ptr = new Master();
    auto boss = boss_ptr[0];
    std::cout << "BOSS has been created!" << std::endl;

    auto ctx = boss.get_context();
    auto sender_ptr = new Slave(ctx);
    auto sender = sender_ptr[0];
    auto receiver_ptr = new Slave(ctx);
    auto receiver = receiver_ptr[0];
    auto attacker_ptr = new Slave(ctx);
    auto attacker = attacker_ptr[0];
    std::cout << "SENDER, RECEIVER and ATTACKER have been created!" << std::endl;

    std::string msg_ref("THIS IS A TEST PLAINTEXT STRING");
    std::cout << "A test string was generated: " << msg_ref << std::endl;

    auto receiver_public_key = receiver.get_public_key();
    auto sender_ciphertext = sender.do_ecnrypt(receiver_public_key, msg_ref);
    std::cout << "Encrypted by SENDER(Y1): " << sender_ciphertext.Y1 << std::endl;
    auto receiver_plaintext = receiver.do_decrypt(sender_ciphertext);
    std::cout << "Decrypted by RECEIVER: " << receiver_plaintext << std::endl;
    auto boss_plaintext = boss.do_decrypt(sender_ciphertext);
    std::cout << "Decrypted by BOSS: " << boss_plaintext << std::endl;
    auto attacker_plaintext = attacker.do_decrypt(sender_ciphertext);
    std::cout << "Decrypted by ATTACKER: " << attacker_plaintext << std::endl;

    delete boss_ptr;
    delete sender_ptr;
    delete receiver_ptr;
    delete attacker_ptr;

    std::cout << "Finish test #1" << std::endl
              << std::endl;

    return;
}

// BOSS SENDS ENCRYPTED SIGNED MESSAGE TO USER
void test_2()
{
    std::cout << "Start test #2 - BOSS SENDS ENCRYPTED SIGNED MESSAGE TO USER" << std::endl;

    auto boss_ptr = new Master();
    auto boss = boss_ptr[0];
    std::cout << "BOSS has been created!" << std::endl;

    auto ctx = boss.get_context();
    auto receiver_ptr = new Slave(ctx);
    auto receiver = receiver_ptr[0];
    std::cout << "RECEIVER has been created!" << std::endl;

    std::string msg_ref("THIS IS A TEST PLAINTEXT STRING");
    std::cout << "A test string was generated: " << msg_ref << std::endl;

    mcl::bn::G2 signature = boss.do_sign(msg_ref);
    std::cout << "Signed by BOSS: " << signature << std::endl;

    auto receiver_public_key = receiver.get_public_key();
    auto boss_ciphertext = boss.do_ecnrypt(receiver_public_key, msg_ref);
    std::cout << "Encrypted by BOSS(Y2): " << boss_ciphertext.Y2 << std::endl;
    auto receiver_plaintext = receiver.do_decrypt(boss_ciphertext);
    std::cout << "Decrypted by RECEIVER: " << receiver_plaintext << std::endl;
    auto boss_public_key = boss.get_public_key();
    std::cout << "Verified by RECEIVER: " << (receiver.do_verify(receiver_plaintext, boss_public_key, signature) ? "YES" : "NO") << std::endl;

    delete boss_ptr;
    delete receiver_ptr;

    std::cout << "Finish test #2" << std::endl
              << std::endl;

    return;
}

// BOSS VERIFIES USER'S SIGNATURE
void test_3()
{
    std::cout << "Start test #3 - BOSS VERIFIES USER'S SIGNATURE" << std::endl;

    auto boss_ptr = new Master();
    auto boss = boss_ptr[0];
    std::cout << "BOSS has been created!" << std::endl;

    auto ctx = boss.get_context();
    auto user_ptr = new Slave(ctx);
    auto user = user_ptr[0];
    std::cout << "USER has been created!" << std::endl;

    auto receiver_ptr = new Slave(ctx);
    auto receiver = receiver_ptr[0];
    std::cout << "RECEIVER has been created!" << std::endl;

    std::string msg_ref("THIS IS A TEST PLAINTEXT STRING");
    std::cout << "A test string was generated: " << msg_ref << std::endl;

    mcl::bn::G2 signature = user.do_sign(msg_ref);
    std::cout << "Signed by USER: " << signature << std::endl;

    auto receiver_public_key = boss.get_public_key();
    auto user_ciphertext = user.do_ecnrypt(receiver_public_key, msg_ref);
    std::cout << "Encrypted by USER(Y1): " << user_ciphertext.Y1 << std::endl;
    auto receiver_plaintext = boss.do_decrypt(user_ciphertext);
    std::cout << "Decrypted by RECEIVER: " << receiver_plaintext << std::endl;
    auto user_public_key = user.get_public_key();
    std::cout << "Verified by RECEIVER: " << (receiver.do_verify(receiver_plaintext, user_public_key, signature) ? "YES" : "NO") << std::endl;
    std::cout << "Verified by BOSS: " << (boss.do_verify(receiver_plaintext, user_public_key, signature) ? "YES" : "NO") << std::endl;

    delete boss_ptr;
    delete user_ptr;
    delete receiver_ptr;

    std::cout << "Finish test #3" << std::endl
              << std::endl;

    return;
}

// KEY EXPANSION
void test_4()
{
    std::cout << "Start test #4 - KEY EXPANSION" << std::endl;

    auto boss_ptr = new Master();
    auto boss = boss_ptr[0];
    std::cout << "BOSS has been created!" << std::endl;

    auto ctx = boss.get_context();
    auto sender_ptr = new Slave(ctx);
    auto sender = sender_ptr[0];
    auto receiver_ptr = new Slave(ctx);
    auto receiver = receiver_ptr[0];
    std::cout << "SENDER and RECEIVER have been created!" << std::endl;

    std::string msg_ref("THIS IS A TEST PLAINTEXT STRING");
    std::cout << "A test string was generated: " << msg_ref << std::endl;

    auto receiver_public_key = receiver.get_public_key();
    auto sender_ciphertext = sender.do_ecnrypt(receiver_public_key, msg_ref);
    std::cout << "Encrypted by SENDER(Y1): " << sender_ciphertext.Y1 << std::endl;
    auto receiver_plaintext = receiver.do_decrypt(sender_ciphertext);
    std::cout << "Decrypted by RECEIVER: " << receiver_plaintext << std::endl;

    auto expansion_ptr = new Slave(ctx);
    auto expansion = sender_ptr[0];
    std::cout << "EXPANSION have been created!" << std::endl;

    auto expansion_public_key = expansion.get_public_key();
    auto sender_ciphertext_exp = sender.do_ecnrypt(expansion_public_key, msg_ref);
    std::cout << "Encrypted by SENDER(Y1): " << sender_ciphertext.Y1 << std::endl;
    auto expansion_plaintext = expansion.do_decrypt(sender_ciphertext_exp);
    std::cout << "Decrypted by EXPANSION: " << expansion_plaintext << std::endl;
    auto boss_plaintext = boss.do_decrypt(sender_ciphertext_exp);
    std::cout << "Decrypted by BOSS: " << boss_plaintext << std::endl;

    delete boss_ptr;
    delete sender_ptr;
    delete receiver_ptr;
    delete expansion_ptr;

    std::cout << "Finish test #4" << std::endl
              << std::endl;

    return;
}

// UNSUCCESSFUL ATTEMPT OF SIGNATURE FORGE
void test_5()
{
    std::cout << "Start test #5 - UNSUCCESSFUL ATTEMPT OF SIGNATURE FORGE" << std::endl;

    auto boss_ptr = new Master();
    auto boss = boss_ptr[0];
    std::cout << "BOSS has been created!" << std::endl;

    auto ctx = boss.get_context();
    auto sender_ptr = new Slave(ctx);
    auto sender = sender_ptr[0];
    std::cout << "SENDER has been created!" << std::endl;

    auto receiver_ptr = new Slave(ctx);
    auto receiver = receiver_ptr[0];
    std::cout << "RECEIVER has been created!" << std::endl;

    std::string msg_ref("THIS IS A TEST PLAINTEXT STRING");
    std::cout << "A test string was generated: " << msg_ref << std::endl;

    auto sender_public_key = sender.get_public_key();

    mcl::bn::G2 signature_sender = sender.do_sign(msg_ref);
    std::cout << "Signed by SENDER: " << signature_sender << std::endl;
    std::cout << "Verified by RECEIVER: " << (receiver.do_verify(msg_ref, sender_public_key, signature_sender) ? "YES" : "NO") << std::endl;

    mcl::bn::G2 signature_boss = boss.do_sign(msg_ref);
    std::cout << "Signed by BOSS: " << signature_boss << std::endl;
    std::cout << "Verified by RECEIVER: " << (receiver.do_verify(msg_ref, sender_public_key, signature_boss) ? "YES" : "NO") << std::endl;

    delete boss_ptr;
    delete sender_ptr;
    delete receiver_ptr;

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
