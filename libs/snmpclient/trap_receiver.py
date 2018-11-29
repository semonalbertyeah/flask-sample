# -*- coding:utf-8 -*-



def test1():
    from pysnmp.carrier.asynsock.dispatch import AsynsockDispatcher
    from pysnmp.carrier.asynsock.dgram import udp, udp6
    from pyasn1.codec.ber import decoder
    from pysnmp.proto import api

    def cbFun(transportDispatcher, transportDomain, transportAddress, wholeMsg):

        while wholeMsg:
            msgVer = int(api.decodeMessageVersion(wholeMsg))
            if msgVer in api.protoModules:
                pMod = api.protoModules[msgVer]
            else:
                print('Unsupported SNMP version %s' % msgVer)
                return

            reqMsg, wholeMsg = decoder.decode(
                    wholeMsg, asn1Spec=pMod.Message(),
                )

            print('Notification message from %s:%s: ' % (
                    transportDomain, transportAddress
                )
            )
            reqPDU = pMod.apiMessage.getPDU(reqMsg)
            if reqPDU.isSameTypeWith(pMod.TrapPDU()):
                if msgVer == api.protoVersion1:
                    print('Enterprise: %s' % (
                            pMod.apiTrapPDU.getEnterprise(reqPDU).prettyPrint()
                        )
                    )
                    print('Agent Address: %s' % (
                            pMod.apiTrapPDU.getAgentAddr(reqPDU).prettyPrint()
                        )
                    )
                    print('Generic Trap: %s' % (
                            pMod.apiTrapPDU.getGenericTrap(reqPDU).prettyPrint()
                        )
                    )
                    print('Specific Trap: %s' % (
                            pMod.apiTrapPDU.getSpecificTrap(reqPDU).prettyPrint()
                        )
                    )
                    print('Uptime: %s' % (
                            pMod.apiTrapPDU.getTimeStamp(reqPDU).prettyPrint()
                        )
                    )
                    varBinds = pMod.apiTrapPDU.getVarBindList(reqPDU)

                else:
                    varBinds = pMod.apiPDU.getVarBindList(reqPDU)

                print('Var-binds:')
                for oid, val in varBinds:
                    print('%s = %s' % (oid.prettyPrint(), val.prettyPrint()))

        return wholeMsg

    transportDispatcher = AsynsockDispatcher()

    transportDispatcher.registerRecvCbFun(cbFun)

    # UDP/IPv4
    transportDispatcher.registerTransport(
        udp.domainName, udp.UdpSocketTransport().openServerMode(('0.0.0.0', 162))
    )

    # # UDP/IPv6
    # transportDispatcher.registerTransport(
    #     udp6.domainName, udp6.Udp6SocketTransport().openServerMode(('::1', 162))
    # )

    transportDispatcher.jobStarted(1)

    try:
        # Dispatcher will never finish as job#1 never reaches zero
        transportDispatcher.runDispatcher()
    except:
        transportDispatcher.closeDispatcher()
        raise



def test2():

    from pysnmp.entity import engine, config
    from pysnmp.carrier.asyncore.dgram import udp
    from pysnmp.entity.rfc3413 import ntfrcv
    from pysnmp.proto.api import v2c
    from pysnmp.smi import builder, view, compiler, rfc1902, error
    from pysnmp import debug 

    debug.setLogger(debug.Debug('all'))
    # snmpEngine = engine.SnmpEngine(snmpEngineID='0x80004fb80567726f6d6d69742')
    snmpEngine = engine.SnmpEngine()

    config.addTransport(
        snmpEngine,
        udp.domainName,
        udp.UdpTransport().openServerMode(('0.0.0.0', 162))
    )

    # config.addV3User(
    #     snmpEngine, 'user_snmp1234'
    # )

    def cbFun(snmpEngine, stateReference, contextEngineId, contextName,
              varBinds, cbCtx):
        print "#######################Recived Notification from {} #######################".format(snmpEngine.msgAndPduDsp.getTransportInfo(stateReference)[-1][0])
        print stateReference, contextEngineId, contextName
        for oid, val in varBinds:
            # output = rfc1902.objecttype(rfc1902.objectidentity(oid),
            #                                  val).resolvewithmib(mibviewcontroller).prettyprint()
            print 'oid:', oid, 'val:', val
            print output

    ntfrcv.NotificationReceiver(snmpEngine, cbFun)
    snmpEngine.transportDispatcher.jobStarted(1) 
    print 'engine:', snmpEngine
    try:
        snmpEngine.transportDispatcher.runDispatcher()
    except:
        snmpEngine.transportDispatcher.closeDispatcher()
        raise



def test3():
    from pysnmp.entity import engine, config
    from pysnmp.carrier.asyncore.dgram import udp
    from pysnmp.entity.rfc3413 import ntfrcv

    # Create SNMP engine with autogenernated engineID and pre-bound
    # to socket transport dispatcher
    snmpEngine = engine.SnmpEngine()

    # Transport setup

    # # UDP over IPv4, first listening interface/port
    # config.addTransport(
    #     snmpEngine,
    #     udp.domainName + (1,),
    #     udp.UdpTransport().openServerMode(('127.0.0.1', 162))
    # )

    # # UDP over IPv4, second listening interface/port
    # config.addTransport(
    #     snmpEngine,
    #     udp.domainName + (2,),
    #     udp.UdpTransport().openServerMode(('127.0.0.1', 2162))
    # )

    config.addTransport(
        snmpEngine,
        udp.domainName,
        udp.UdpTransport().openServerMode(('0.0.0.0', 162))
    )


    # SNMPv1/2c setup

    # SecurityName <-> CommunityName mapping
    config.addV1System(snmpEngine, 'my-area', 'public')


    # Callback function for receiving notifications
    # noinspection PyUnusedLocal,PyUnusedLocal,PyUnusedLocal
    def cbFun(snmpEngine, stateReference, contextEngineId, contextName,
              varBinds, cbCtx):
        print('Notification from ContextEngineId "%s", ContextName "%s"' % (contextEngineId.prettyPrint(),
                                                                            contextName.prettyPrint()))
        for name, val in varBinds:
            print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))


    # Register SNMP Application at the SNMP engine
    ntfrcv.NotificationReceiver(snmpEngine, cbFun)

    print 'dispatcher:', snmpEngine.transportDispatcher
    snmpEngine.transportDispatcher.jobStarted(1)  # this job would never finish

    # Run I/O dispatcher which would receive queries and send confirmations
    try:
        snmpEngine.transportDispatcher.runDispatcher()
    except:
        snmpEngine.transportDispatcher.closeDispatcher()
        raise



if __name__ == '__main__':
    test3()

