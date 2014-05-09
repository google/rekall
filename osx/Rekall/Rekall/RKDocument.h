//
//  RKDocument.h
//  Rekall
//
//  Created by Adam Sindelar on 5/8/14.
//  Copyright (c) 2014 Rekall. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>

@interface RKDocument : NSDocument

@property (retain) IBOutlet WebView *webView;
@property (retain) IBOutlet NSProgressIndicator *spinner;

@end
