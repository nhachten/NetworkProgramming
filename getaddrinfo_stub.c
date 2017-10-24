int
getaddrinfo(const char *hostname, const char *servname,
    const struct addrinfo *hints, struct addrinfo **res)
{
	struct addrinfo sentinel;
	struct addrinfo *cur;
	int error = 0;
	struct addrinfo ai, ai0, *afai;
	struct addrinfo *pai;
	const struct afd *afd;
	const struct explore *ex;
	struct addrinfo *afailist[sizeof(afdl)/sizeof(afdl[0])];
	struct addrinfo *afai_unspec;
	int found;
	int numeric = 0;

	/* ensure we return NULL on errors */
	*res = NULL;

	memset(&ai, 0, sizeof(ai));

	memset(afailist, 0, sizeof(afailist));
	afai_unspec = NULL;

	memset(&sentinel, 0, sizeof(sentinel));
	cur = &sentinel;
	pai = &ai;
	pai->ai_flags = 0;
	pai->ai_family = PF_UNSPEC;
	pai->ai_socktype = ANY;
	pai->ai_protocol = ANY;
	pai->ai_addrlen = 0;
	pai->ai_canonname = NULL;
	pai->ai_addr = NULL;
	pai->ai_next = NULL;

	if (hostname == NULL && servname == NULL)
		return EAI_NONAME;
	if (hints) {
		/* error check for hints */
		if (hints->ai_addrlen || hints->ai_canonname ||
		    hints->ai_addr || hints->ai_next)
			ERR(EAI_BADHINTS); /* xxx */
		if (hints->ai_flags & ~AI_MASK)
			ERR(EAI_BADFLAGS);
		switch (hints->ai_family) {
		case PF_UNSPEC:
		case PF_INET:
#ifdef INET6
		case PF_INET6:
#endif
			break;
		default:
			ERR(EAI_FAMILY);
		}
		memcpy(pai, hints, sizeof(*pai));

		/*
		 * if both socktype/protocol are specified, check if they
		 * are meaningful combination.
		 */
		if (pai->ai_socktype != ANY && pai->ai_protocol != ANY) {
			for (ex = explore; ex->e_af >= 0; ex++) {
				if (!MATCH_FAMILY(pai->ai_family, ex->e_af,
				    WILD_AF(ex)))
					continue;
				if (!MATCH(pai->ai_socktype, ex->e_socktype,
				    WILD_SOCKTYPE(ex)))
					continue;
				if (!MATCH(pai->ai_protocol, ex->e_protocol,
				    WILD_PROTOCOL(ex)))
					continue;

				/* matched */
				break;
			}

			if (ex->e_af < 0)
				ERR(EAI_BADHINTS);
		}
	}

	/*
	 * check for special cases.  (1) numeric servname is disallowed if
	 * socktype/protocol are left unspecified. (2) servname is disallowed
	 * for raw and other inet{,6} sockets.
	 */
	if (MATCH_FAMILY(pai->ai_family, PF_INET, 1)
#ifdef PF_INET6
	    || MATCH_FAMILY(pai->ai_family, PF_INET6, 1)
#endif
	    ) {
		ai0 = *pai;	/* backup *pai */

		if (pai->ai_family == PF_UNSPEC) {
#ifdef PF_INET6
			pai->ai_family = PF_INET6;
#else
			pai->ai_family = PF_INET;
#endif
		}
		error = get_portmatch(pai, servname);
		if (error)
			goto bad;

		*pai = ai0;
	}

	ai0 = *pai;

	/*
	 * NULL hostname, or numeric hostname.
	 * If numeric representation of AF1 can be interpreted as FQDN
	 * representation of AF2, we need to think again about the code below.
	 */
	found = 0;
	for (afd = afdl; afd->a_af; afd++) {
		*pai = ai0;

		if (!MATCH_FAMILY(pai->ai_family, afd->a_af, 1))
			continue;

		if (pai->ai_family == PF_UNSPEC)
			pai->ai_family = afd->a_af;

		if (hostname == NULL) {
			error = explore_null(pai, servname,
			    &afailist[afd - afdl]);

			/*
			 * Errors from explore_null should be unexpected and
			 * be caught to avoid returning an incomplete result.
			 */
			if (error != 0)
				goto bad;
		} else {
			error = explore_numeric_scope(pai, hostname, servname,
			    &afailist[afd - afdl]);

			/*
			 * explore_numeric_scope returns an error for address
			 * families that do not match that of hostname.
			 * Thus we should not catch the error at this moment. 
			 */
		}

		if (!error && afailist[afd - afdl])
			found++;
	}
	if (found) {
		numeric = 1;
		goto globcopy;
	}

	if (hostname == NULL)
		ERR(EAI_NONAME);	/* used to be EAI_NODATA */
	if (pai->ai_flags & AI_NUMERICHOST)
		ERR(EAI_NONAME);

	if ((pai->ai_flags & AI_ADDRCONFIG) != 0 && !addrconfig(&ai0))
		ERR(EAI_FAIL);

	/*
	 * hostname as alphabetical name.
	 */
	*pai = ai0;
	error = explore_fqdn(pai, hostname, servname, &afai_unspec);

globcopy:
	for (ex = explore; ex->e_af >= 0; ex++) {
		*pai = ai0;

		if (!MATCH_FAMILY(pai->ai_family, ex->e_af, WILD_AF(ex)))
			continue;
		if (!MATCH(pai->ai_socktype, ex->e_socktype,
		    WILD_SOCKTYPE(ex)))
			continue;
		if (!MATCH(pai->ai_protocol, ex->e_protocol,
		    WILD_PROTOCOL(ex)))
			continue;

		if (pai->ai_family == PF_UNSPEC)
			pai->ai_family = ex->e_af;
		if (pai->ai_socktype == ANY && ex->e_socktype != ANY)
			pai->ai_socktype = ex->e_socktype;
		if (pai->ai_protocol == ANY && ex->e_protocol != ANY)
			pai->ai_protocol = ex->e_protocol;

		/*
		 * if the servname does not match socktype/protocol, ignore it.
		 */
		if (get_portmatch(pai, servname) != 0)
			continue;

		if (afai_unspec)
			afai = afai_unspec;
		else {
			if ((afd = find_afd(pai->ai_family)) == NULL)
				continue;
			/* XXX assumes that afd points inside afdl[] */
			afai = afailist[afd - afdl];
		}
		if (!afai)
			continue;

		error = explore_copy(pai, afai, &cur->ai_next);
		if (error != 0)
			goto bad;

		while (cur && cur->ai_next)
			cur = cur->ai_next;
	}

	/*
	 * ensure we return either:
	 * - error == 0, non-NULL *res
	 * - error != 0, NULL *res
	 */
	if (error == 0) {
		if (sentinel.ai_next) {
			/*
			 * If the returned entry is for an active connection,
			 * and the given name is not numeric, reorder the
			 * list, so that the application would try the list
			 * in the most efficient order.  Since the head entry
			 * of the original list may contain ai_canonname and
			 * that entry may be moved elsewhere in the new list,
			 * we keep the pointer and will  restore it in the new
			 * head entry.  (Note that RFC3493 requires the head
			 * entry store it when requested by the caller).
			 */
			if (hints == NULL || !(hints->ai_flags & AI_PASSIVE)) {
				if (!numeric) {
					char *canonname;

					canonname =
					    sentinel.ai_next->ai_canonname;
					sentinel.ai_next->ai_canonname = NULL;
					(void)reorder(&sentinel);
					if (sentinel.ai_next->ai_canonname ==
					    NULL) {
						sentinel.ai_next->ai_canonname
						    = canonname;
					} else if (canonname != NULL)
						free(canonname);
				}
			}
			*res = sentinel.ai_next;
		} else
			error = EAI_FAIL;
	}

bad:
	if (afai_unspec)
		freeaddrinfo(afai_unspec);
	for (afd = afdl; afd->a_af; afd++) {
		if (afailist[afd - afdl])
			freeaddrinfo(afailist[afd - afdl]);
	}
	if (!*res)
		if (sentinel.ai_next)
			freeaddrinfo(sentinel.ai_next);

	return (error);
}
