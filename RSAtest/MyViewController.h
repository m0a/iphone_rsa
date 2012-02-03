//
//  MyViewController.h
//  RSAtest
//
//  Created by 阿部 誠 on 12/02/03.
//  Copyright (c) 2012年 __MyCompanyName__. All rights reserved.
//

#import <UIKit/UIKit.h>

SecKeyRef oPublicKey;
SecKeyRef oPrivateKey;

SecKeyRef publicKey;
SecKeyRef privateKey; 

uint8_t *plainBuffer;
uint8_t *cipherBuffer;
uint8_t *decryptedBuffer;

const size_t BUFFER_SIZE = 64;
const size_t CIPHER_BUFFER_SIZE = 1024;
const uint32_t PADDING = kSecPaddingNone;

@interface MyViewController : UIViewController
@property (weak, nonatomic) IBOutlet UITextField *tf;
@property (weak, nonatomic) IBOutlet UILabel *ent;
@property (weak, nonatomic) IBOutlet UILabel *det;
- (IBAction)start:(id)sender;

- (void)generateKeyPairRSA;
-(void)Encryption;
-(void)Decryption;


@end
