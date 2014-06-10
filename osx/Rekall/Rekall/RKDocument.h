//
//  RKDocument.h
//  Rekall
//
//  Created by Adam Sindelar on 5/8/14.
//  Copyright (c) 2014 Rekall. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>

#import "RKSessionWrapper.h"

/** This main document class handles loading of raw memory images, as well as saving and restoring
 *  Rekall sessions.
 */
@interface RKDocument : NSDocument

/** The WebView we wrap around to display the webconsole. */
@property (nonatomic, strong) IBOutlet WebView *webView;

/** Displayed before the WebView is ready. */
@property (nonatomic, strong) IBOutlet NSProgressIndicator *spinner;

/** The rekall python instance we're connected to. */
@property (strong) RKSessionWrapper *rekall;

/** The (HTTP) URL that rekall's webconsole is running at. */
@property (copy) NSURL *rekallURL;

@end
