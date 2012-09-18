#ifndef H_Exceptions
#define H_Exceptions

#include <stdexcept>
#include <string>

/*! 
 * Base exception class for TLSA fetcher plugin.
 * 
 * Members are marked as throw(), though in pure theory they could throw
 * bad_alloc because of the string member, which would result in abort.
 */
class TLSAfetcherException: public std::exception
{
public:
    
    /*! Constructor from C-style string */
    TLSAfetcherException(const char *msg) throw():
        std::exception(),
        m_message(msg)
        {}

    /*! Constructor from STL-style string */
    TLSAfetcherException(const std::string &msg) throw():
        std::exception(),
        m_message(msg)
        {}

    virtual ~TLSAfetcherException() throw()
        {}
    
    /*! Undefined copy constructor */    
    TLSAfetcherException(const TLSAfetcherException& ) throw();
    
    /*! Undefined assignment operator */
    TLSAfetcherException& operator= (const TLSAfetcherException& ) throw();
    
    /*! Exception message */
    virtual const char * what() const throw()
        {return m_message.c_str();}
    
    /*! Exception message */
    virtual const std::string& message() const throw()
        {return m_message;}

protected:
    
    /*! Exception message */
    std::string m_message; 
};

/*! Exception for signaling resolving or DNS parsing errors. */
class ResolverException: public TLSAfetcherException
{
public:

    ResolverException(const char  *msg) throw():
    	TLSAfetcherException(msg)
        {}
      
    ResolverException(const std::string& msg) throw():
    	TLSAfetcherException(msg)
        {}
};


class CertificateError: public TLSAfetcherException
{
public:
    
    CertificateError(const char* msg) throw():
        TLSAfetcherException(msg)
        {}
    CertificateError(const std::string& msg) throw():
        TLSAfetcherException(msg)
        {}
};


#endif // H_Exceptions
