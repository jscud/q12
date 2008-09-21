# Copyright (C) 2008 Jeffrey William Scudder.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app


class Echo(webapp.RequestHandler):
  
  def get(self):
    for key, value in self.request.headers.iteritems():
      self.response.headers.add_header(key, value)
    self.response.set_status(200, 'OK')
    self.response.out.write('This is a test.')
    
  def post(self):
    for key, value in self.request.headers.iteritems():
      self.response.headers.add_header(key, value)
    self.response.set_status(201, 'CREATED')
    self.response.out.write(self.request.body)
    
  def put(self):
    for key, value in self.request.headers.iteritems():
      self.response.headers.add_header(key, value)
    self.response.set_status(200, 'UPDATED')
    self.response.out.write(self.request.body)
    
  def delete(self):
    for key, value in self.request.headers.iteritems():
      self.response.headers.add_header(key, value)
    self.response.set_status(200, 'DELETED')
  

application = webapp.WSGIApplication([('/echo.*', Echo),
                                     ],
                                     debug=True)

def main():
  run_wsgi_app(application)

  
if __name__ == '__main__':
  main()
