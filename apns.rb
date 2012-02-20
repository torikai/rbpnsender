#! /usr/bin/env ruby

require 'rubygems'
require 'json'
require 'socket'
require 'openssl'

include OpenSSL::SSL

class APNS_Socket 
	URL = 'gateway.sandbox.push.apple.com'
	PORT = 2195

	attr_accessor :cert, :key
	attr_reader :socket

	def initialize(cert, key)
		@cert = cert, @key = key
		@socket = SSLSocket.new(TCPSocket.new(URL, PORT), 
								context(cert, key))
		@socket.sync_close = true
	end

	def APNS_Socket.open(cert, key)
		socket = APNS_Socket.new(cert, key)
		yield socket if socket.connect
	end

	def connect
		begin
			@socket.connect
			@socket.post_connection_check URL
		rescue
			puts "connect failed"
			return false
		end
		true
	end

	def context(cert, key)
		ctx = SSLContext.new
		ctx.verify_mode = VERIFY_PEER | VERIFY_FAIL_IF_NO_PEER_CERT
		ctx.cert = OpenSSL::X509::Certificate.new(File.read cert)
		ctx.key = OpenSSL::PKey::RSA.new(File.read key)
		ctx
	end

	def send_msg(devices, msg)
		devices.each do |device| 
			@socket.syswrite(pack_msg device, msg)
		end
	end

	def pack_msg(device, msg)
		payload = JSON.generate({ "aps" => msg })
		[0].pack("c") + [device.size / 2].pack("n") + [device].pack("H*") + 
			[payload.size].pack("n") + payload
	end

end

devices = [""] #device token

APNS_Socket.open("ck.pem", "key.rsa") do |sock|
	sock.send_msg(devices, :alert => "message", 
				  		   :badge => 1,
						   :sound => "sub.caf")
end

