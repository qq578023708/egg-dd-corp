declare module 'egg' {
  interface Application {
    dd: {
      jsapiConfig(url: string): Promise<void>;
      getDept(id: number | string): Promise<any>;
      getDeptList(parentId?: number | string, recursion?: boolean): Promise<[any]>;
      getRoleTree(): Promise<[any]>;
      getDeptUserList(departmentId: number | string): Promise<[any]>;
      getRoleUserList(roleId: number | string): Promise<[any]>;
      getUserId(code: string): Promise<string>;
      getUser(ddUserId: string): Promise<object>;
      getUrl(): Promise<void>;
      setUrl(tags: Array<string>, url: string, type?: string): Promise<void>;
      delUrl(): Promise<void>;
      decrypt(text: string): string;
      callback(text?: string): object;
      getAttCols(): Promise<void>;
      getColsVal(ddUserId: string, colIds: string, from: string, to: string): Promise<void>;
      getLeaveVal(ddUserId: string, leaveNames: string, from: string, to: string): Promise<void>;
      createTodo(data: object): Promise<void>;
      updateTodo(ddUserId: string, recordId: string): Promise<void>;
      getCallbackError(): Promise<[any]>;
      createEvent(event: object): Promise<void>
    };
  }
}
