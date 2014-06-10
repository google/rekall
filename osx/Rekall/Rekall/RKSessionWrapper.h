//
//  RKSessionWrapper.h
//  Rekall
//
//  Created by Adam Sindelar on 5/8/14.
//  Copyright (c) 2014 Rekall. All rights reserved.
//

#import <Foundation/Foundation.h>

/** RKSessionWrapper.port will be set to this value until it's set to a real value. */
extern const NSInteger RKNullPortNumberSentinel;

/** Error domain for all errors encountered while talking to the python rekall instance. */
extern NSString *const RKErrorDomain;

/** Key used to store error title in the userInfo dict of errors in the RKErrorDomain. */
extern NSString *const RKErrorTitle;

/** Key used to store error description in the userInfo dict of errors in the RKErrorDomain. */
extern NSString *const RKErrorDescription;

/** Error number for unspecified error when talking to python rekall instance. */
#define RKSessionRekallError 500

/** This class is responsible for executing a rekall python instance, launching a web console
 *  session, figuring out the port it binds to and making that information available.
 */
@interface RKSessionWrapper : NSObject

/** The port number on loopback that the rekall webconsole is running its HTTP server.
 *  This is initialized to RKNullPortNumberSentinel and stays that way until the real port is known.
 */
@property (assign, readonly, nonatomic) NSInteger port;

/** Callback once the web session is up and the port is known. */
@property (copy, nonatomic) void (^onLaunchCallback)(void);

/** Callback in case errors are encountered. */
@property (copy, nonatomic) void (^onErrorCallback)(NSError *error);

/** Will start a rekall instance on image at path and launch a webconsole.
 *  On success, will call onLaunchCallback. On failure, will either fill errorBuf or call
 *  onErrorCallback, depending on when the error occurs.
 *
 *  @param path The path to a memory image to be passed to rekall process.
 *  @param errorBuf Will be populated with an NSError instance in case of immediate errors.
 *  @return NO if errorBuf is filled, otherwise YES.
 */
- (BOOL)startWebconsoleWithImage:(NSURL *)path error:(NSError **)errorBuf;

/** Will terminate the current rekall instance, if any. */
- (void)stopRekallWebconsoleSession;

@end
