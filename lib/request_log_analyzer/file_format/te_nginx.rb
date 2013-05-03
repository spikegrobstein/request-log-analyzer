module RequestLogAnalyzer::FileFormat

  # file format for te nginx logs
  class TeNginx < Base

    extend CommonRegularExpressions

    line_definition :access do |line|
      line.header = true
      line.footer = true
      # line.regexp = /^([^\ ]+) ([^\ ]+) \[(#{timestamp('%d/%b/%Y:%H:%M:%S %z')})?\] (#{ip_address}) ([^\ ]+) ([^\ ]+) (\w+(?:\.\w+)*) ([^\ ]+) "([^"]+)" (\d+) ([^\ ]+) (\d+) (\d+) (\d+) (\d+) "([^"]*)" "([^"]*)"/
      line.regexp = /^([^\s]+) (#{ip_address}) (\d+) ([^\s]+) (\d+) (\d+) ([\d\.]+) ([A-Za-z]+) (.+)\??/
      # line.regexp = /^([^\s]+) ([^\s]+) (\d+)/

      line.capture(:timestamp).as(:timestamp)
      line.capture(:remote_ip)
      line.capture(:request_size)
      line.capture(:api_token).as(:nillable_string)
      line.capture(:http_status).as(:integer)
      line.capture(:response_size).as(:integer, :unit => :byte)
      line.capture(:request_time).as(:duration, :unit => :sec)
      line.capture(:http_method)
      line.capture(:request_uri)
    end

    report do |analyze|
      analyze.timespan
      analyze.hourly_spread

      analyze.frequency :category => lambda { |r| "#{r[:http_method]} #{r[:request_uri]}"}, :title => "Most popular URI"
      analyze.frequency :category => lambda { |r| "#{r[:api_token]}"}, :title => "Most popular API Token"

      analyze.duration :duration => :request_time, :category => lambda { |r| "#{r[:http_method]} #{r[:request_uri]}"}, :title => "Request duration"
      analyze.traffic  :traffic => :response_size,  :category => lambda { |r| "#{r[:http_method]} #{r[:request_uri]}"}, :title => "Traffic"
      analyze.frequency :category => :http_status, :title => 'HTTP status codes'
      # analyze.frequency :category => :error_code, :title => 'Error codes'
    end

    class Request < RequestLogAnalyzer::Request

      MONTHS = {'Jan' => '01', 'Feb' => '02', 'Mar' => '03', 'Apr' => '04', 'May' => '05', 'Jun' => '06',
                'Jul' => '07', 'Aug' => '08', 'Sep' => '09', 'Oct' => '10', 'Nov' => '11', 'Dec' => '12' }

      # Do not use DateTime.parse, but parse the timestamp ourselves to return a integer
      # to speed up parsing.
      def convert_timestamp(value, definition)
        #2013-05-03T06:25:03+00:00
        #0123456789012345678
        "#{value[0,4]}#{value[5,2]}#{value[8,2]}#{value[11,2]}#{value[14,2]}#{value[17,2]}".to_i
        # "#{value[7,4]}#{MONTHS[value[3,3]]}#{value[0,2]}#{value[12,2]}#{value[15,2]}#{value[18,2]}".to_i
      end

      def convert_request_time(value, definition)
        raise ""
      end

      # Make sure that the string '-' is parsed as a nil value.
      def convert_nillable_string(value, definition)
        value == '-' ? nil : value
      end

      # Can be implemented in subclasses for improved categorizations
      def convert_referer(value, definition)
        value == '-' ? nil : value
      end

      # Can be implemented in subclasses for improved categorizations
      def convert_user_agent(value, definition)
        value == '-' ? nil : value
      end
    end

  end
end
