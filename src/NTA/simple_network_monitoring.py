def _monitor_loop(self) -> None:
        """Main monitoring loop - non-privileged version"""
        logger.info(f"Starting network monitoring on interface: {self.interface}")
        self.stats['start_time'] = time.time()
        
        print(f"\n{'='*60}")
        print("🚀 CHRONOS AI GUARD - NETWORK TRAFFIC ANALYSIS")
        print("⚡ NON-PRIVILEGED MODE (Simulated Packets)")
        print(f"{'='*60}")
        print(f"📡 Interface: {self.interface}")
        print(f"⏱️  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"📦 Packet limit: {self.packet_limit if self.packet_limit > 0 else 'Unlimited'}")
        print(f"{'='*60}")
        print("📊 Press Ctrl+C to stop monitoring")
        print(f"{'='*60}\n")
        
        packet_count = 0
        
        try:
            while self.is_monitoring and (self.packet_limit == 0 or packet_count < self.packet_limit):
                try:
                    # Simulate packet generation instead of real capture
                    time.sleep(0.01)  # 10ms between packets
                    
                    # Create simulated packet
                    packet_info = self._parse_packet(None)
                    if packet_info:
                        self._process_packet_info(packet_info)
                        packet_count += 1
                    
                    # Display statistics every 100 packets
                    if packet_count % 100 == 0:
                        self._display_stats()
                        
                except Exception as e:
                    logger.error(f"Error in monitoring loop: {e}")
                    time.sleep(1)
                    
        except KeyboardInterrupt:
            print("\n\n🛑 Monitoring interrupted by user")
        except Exception as e:
            logger.error(f"Monitoring error: {e}")
        finally:
            self.is_monitoring = False
