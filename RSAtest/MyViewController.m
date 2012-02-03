//
//  MyViewController.m
//  RSAtest
//
//  Created by 阿部 誠 on 12/02/03.
//  Copyright (c) 2012年 __MyCompanyName__. All rights reserved.
//

#import "MyViewController.h"
#import <Security/Security.h>


@implementation MyViewController
@synthesize tf;
@synthesize ent;
@synthesize det;

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Release any cached data, images, etc that aren't in use.
}

#pragma mark - View lifecycle

- (void)viewDidLoad
{
    [super viewDidLoad];
	// Do any additional setup after loading the view, typically from a nib.
    //[self generateKeyPairRSA];
    
}

- (void)viewDidUnload
{
    [self setTf:nil];
    [self setEnt:nil];
    [self setDet:nil];
    [super viewDidUnload];
    // Release any retained subviews of the main view.
    // e.g. self.myOutlet = nil;
}

- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
}

- (void)viewDidAppear:(BOOL)animated
{
    [super viewDidAppear:animated];
}

- (void)viewWillDisappear:(BOOL)animated
{
	[super viewWillDisappear:animated];
}

- (void)viewDidDisappear:(BOOL)animated
{
	[super viewDidDisappear:animated];
}

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation
{
    // Return YES for supported orientations
    return (interfaceOrientation != UIInterfaceOrientationPortraitUpsideDown);
}

static const UInt8 publicKeyIdentifier[] = "com.apple.sample.publickey222\0";
static const UInt8 privateKeyIdentifier[] = "com.apple.sample.privatekey111\0";

- (IBAction)start:(id)sender {
    [self generateKeyPairRSA];
    [self Encryption];
    [self Decryption];
}

- (void)generateKeyPairRSA
{
    OSStatus status = noErr;    
    NSMutableDictionary *privateKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary *publicKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary *keyPairAttr = [[NSMutableDictionary alloc] init];
    
    NSData * publicTag = [NSData dataWithBytes:publicKeyIdentifier 
                                        length:strlen((const char *)publicKeyIdentifier)];
    
    NSData * privateTag = [NSData dataWithBytes:privateKeyIdentifier
                                        length:strlen((const char *)privateKeyIdentifier)];
    
    publicKey = NULL;
    privateKey = NULL;
    
    [keyPairAttr setObject:(__bridge_transfer id)kSecAttrKeyTypeRSA
                    forKey:(__bridge_transfer id)kSecAttrKeyType];
    
    [keyPairAttr setObject:[NSNumber numberWithInt:1024]
                    forKey:(__bridge_transfer id)kSecAttrKeySizeInBits];
    
    [privateKeyAttr setObject:[NSNumber numberWithBool:YES]
                       forKey:(__bridge_transfer id)kSecAttrIsPermanent];
    
    [privateKeyAttr setObject:privateTag
                       forKey:(__bridge_transfer id)kSecAttrApplicationTag];
    
    [publicKeyAttr setObject:[NSNumber numberWithBool:YES]
                      forKey:(__bridge_transfer id)kSecAttrIsPermanent];
    
    [publicKeyAttr setObject:publicTag
                      forKey:(__bridge_transfer id)kSecAttrApplicationTag];
    
    [keyPairAttr setObject:privateKeyAttr    
                    forKey:(__bridge_transfer id)kSecPrivateKeyAttrs];
    
    [keyPairAttr setObject:publicKeyAttr
                    forKey:(__bridge_transfer id)kSecPublicKeyAttrs];
    
    status = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttr,
                                &publicKey, &privateKey);
}

- (SecKeyRef)getPublicKeyRef {
    OSStatus resultCode = noErr;
    SecKeyRef publicKeyReference = NULL;
    
    if(publicKey == NULL) {
        NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
        
        NSData *publicTag = [NSData dataWithBytes:publicKeyIdentifier
                             
                                           length:strlen((const char *)publicKeyIdentifier)]; 
        
        // Set the public key query dictionary.
        [queryPublicKey setObject:(__bridge_transfer id)kSecClassKey forKey:(__bridge_transfer id)kSecClass];
        
        [queryPublicKey setObject:publicTag forKey:(__bridge_transfer id)kSecAttrApplicationTag];
        
        [queryPublicKey setObject:(__bridge_transfer id)kSecAttrKeyTypeRSA forKey:(__bridge_transfer id)kSecAttrKeyType];
        
        [queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge_transfer id)kSecReturnRef];
        
        // Get the key.
        resultCode = SecItemCopyMatching((__bridge CFDictionaryRef)queryPublicKey, (CFTypeRef *)&publicKeyReference);
        NSLog(@"getPublicKey: result code: %ld", resultCode);
        
        if(resultCode != noErr)
        {
            publicKeyReference = NULL;
        }
        
        queryPublicKey =nil;
    } else {
        publicKeyReference = publicKey;
    }
    
    return publicKeyReference;
}


- (void)encryptWithPublicKey:(uint8_t *)plainBuffer cipherBuffer:(uint8_t *)cipherBuffer
{
    //  NSLog(@"== encryptWithPublicKey()");
    
    OSStatus status = noErr;
    
    //NSLog(@"** original plain text 0: %s", plainBuffer);
    
    size_t plainBufferSize = strlen((char *)plainBuffer);
    size_t cipherBufferSize = CIPHER_BUFFER_SIZE;
    SecKeyRef key=[self getPublicKeyRef];
    NSLog(@"SecKeyGetBlockSize() public = %lu", SecKeyGetBlockSize(key));
    //  Error handling
    // Encrypt using the public.
    status = SecKeyEncrypt([self getPublicKeyRef],
                           PADDING,
                           plainBuffer,
                           plainBufferSize,
                           &cipherBuffer[0],
                           &cipherBufferSize
                           );
    // NSLog(@"encryption result code: %d (size: %d)", status, cipherBufferSize);
    NSLog(@"encrypted text: %s", cipherBuffer);
}

-(void)Encryption
{
    
    
    const char *inputString;
    inputString=[tf.text cStringUsingEncoding: NSASCIIStringEncoding];
    int len = strlen(inputString);
    if (len > BUFFER_SIZE) len = BUFFER_SIZE-1;
    
    plainBuffer = (uint8_t *)calloc(BUFFER_SIZE, sizeof(uint8_t));
    cipherBuffer = (uint8_t *)calloc(CIPHER_BUFFER_SIZE, sizeof(uint8_t));
    decryptedBuffer = (uint8_t *)calloc(BUFFER_SIZE, sizeof(uint8_t));
    
    strncpy( (char *)plainBuffer,inputString, len);
    
    NSLog(@"init() plainBuffer: %s", plainBuffer);
    [self encryptWithPublicKey:(UInt8 *)plainBuffer cipherBuffer:cipherBuffer];
    NSLog(@"encrypted data: %s", cipherBuffer);
    
    NSMutableData *data=[[NSMutableData alloc] init];
    [data appendBytes:cipherBuffer length:strlen( (char*)cipherBuffer ) + 1];
    
    NSString *string = [[NSString alloc]initWithData:data encoding:NSASCIIStringEncoding];
    ent.text=string;
}

- (SecKeyRef)getPrivateKeyRef {
    OSStatus resultCode = noErr;
    SecKeyRef privateKeyReference = NULL;
    
    if(privateKey == NULL) {
        NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
        NSData *privateTag = [NSData dataWithBytes:privateKeyIdentifier
                              
                                            length:strlen((const char *)privateKeyIdentifier)]; 
        // Set the private key query dictionary.
        [queryPrivateKey setObject:(__bridge_transfer id)kSecClassKey forKey:(__bridge_transfer id)kSecClass];
        [queryPrivateKey setObject:privateTag forKey:(__bridge_transfer id)kSecAttrApplicationTag];
        [queryPrivateKey setObject:(__bridge_transfer id)kSecAttrKeyTypeRSA forKey:(__bridge_transfer id)kSecAttrKeyType];
        [queryPrivateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge_transfer id)kSecReturnRef];
        
        // Get the key.
        resultCode = SecItemCopyMatching((__bridge_retained CFDictionaryRef)queryPrivateKey, (CFTypeRef *)&privateKeyReference);
        NSLog(@"getPrivateKey: result code: %ld", resultCode);
        
        if(resultCode != noErr)
        {
            privateKeyReference = NULL;
        }
        
        queryPrivateKey = nil;
    } else {
        privateKeyReference = privateKey;
    }
    
    return privateKeyReference;
}

- (void)decryptWithPrivateKey:(uint8_t *)cipherBuffer plainBuffer:(uint8_t *)plainBuffer
{
    OSStatus status = noErr;
    
    size_t cipherBufferSize = strlen((char *)cipherBuffer);
    
    NSLog(@"decryptWithPrivateKey: length of buffer: %lu", BUFFER_SIZE);
    NSLog(@"decryptWithPrivateKey: length of input: %lu", cipherBufferSize);
    
    // DECRYPTION
    size_t plainBufferSize = BUFFER_SIZE;
    
    //  Error handling
    status = SecKeyDecrypt([self getPrivateKeyRef],
                           PADDING,
                           &cipherBuffer[0],
                           cipherBufferSize,
                           &plainBuffer[0],
                           &plainBufferSize
                           );
    NSLog(@"decryption result code: %ld (size: %lu)", status, plainBufferSize);
    NSLog(@"FINAL decrypted text: %s", plainBuffer);
    
}

-(void)Decryption
{
    const char inputString[] = "this is a test.  this is only a test.  please remain calm.";
    int len = strlen(inputString);
    if (len > BUFFER_SIZE) len = BUFFER_SIZE-1;
    
    strncpy( (char *)plainBuffer, inputString, len);
    
    NSLog(@"CIPHER %s",cipherBuffer);
    [self decryptWithPrivateKey:cipherBuffer plainBuffer:decryptedBuffer];
    NSLog(@"decrypted data: %s", decryptedBuffer);
    NSMutableData *data=[[NSMutableData alloc] init];
    [data appendBytes:decryptedBuffer length:strlen( (char*)decryptedBuffer ) + 1];
    
    NSString *string = [[NSString alloc]initWithData:data encoding:NSASCIIStringEncoding];
    det.text=string;
    
}
@end
