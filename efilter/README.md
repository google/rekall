# EFILTER Query Language

EFILTER is a general-purpose destructuring and search language implemented in Python, and suitable for integration with any Python project that requires a search function for some of its data.

## Quick Example

	query = Query("name == 'Bob' and age > (15 + 1)")
	query.run_engine("matcher", dict(name="Alice", age=20)) # => False
	query.run_engine("matcher", dict(name="Bob", age=20)) # => True
	query.run_engine("infer_types") # => bool
	Query("15 + 1").run_engine("infer_types") # => int

## Integrating EFILTER with your project

### Filtering custom classes

Let's have a class in our custom project:

	class Customer(object):
		"""My awesome Customer business logic class."""
		
		@property
		def name(self):
			#...
		
		@property
		def age(self):
			#...
		
		@property
		def admin(self):
			#...

We'd like to filter this class's instances using EFILTER, but we need a way to
'tell' EFILTER about it. 

EFILTER uses the IAssociative protocol to access members of the objects its
asked to filter. Implementing a protocol lets EFILTER know how each type should
be accessed:

	from efilter.protocols import associative
	associative.IAssociative.implement(
		for_type=Customer,  # This is how you access Customer's data.
		implementations={
			# Select is similar to dict().get()
			associative.select: lambda c, key: getattr(c, key, None),
			
			# Resolve is similar, but allowed to use magic to look
			# up more data. For example, selecting 'admin' will
			# return the ID of the admin user, but resolving
			# 'admin' might return the user object representing
			# the admin.
			associative.resolve: lambda c, key: getattr(c, key, None),
			
			# Getkeys is kind of obvious: the keys that can be
			# accessed.
			associative.getkeys: lambda _: ("name", "age", "admin")
		})

Now we can filter the Customer class:

	query = Query("name == 'Bob'")
	query.run_engine("matcher", bindings=Customer(name="Bob")) # => True

## License and Copyright

Copyright 2015 Google Inc. All Rights Reserved

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0).

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Contributors

[Adam Sindelar](https://github.com/the80srobot)
